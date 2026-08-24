#![doc = "Safe JSON-only control CLI for device certificate rotation."]

use std::{
    fs,
    future::Future,
    io::{self, Read},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, error::ErrorKind};
use futures_util::StreamExt;
use openidconnect::{
    AdditionalClaims, ClientId, IdToken, IssuerUrl, Nonce, PkceCodeChallenge,
    core::{
        CoreGenderClaim, CoreIdTokenVerifier, CoreJsonWebKeySet, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    },
};
use reqwest::{
    Client, Method, StatusCode,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
};
use rotation_model::{KeyUsage, RotationPolicy};
use rss_device_security_client::{
    Diagnostic, DiagnosticKind, PolicyResponse, StatusResponse, decode_policy_response,
    decode_status_response, prepare_policy_put, prepare_status_get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{Instant, timeout, timeout_at},
};
use url::Url;
use uuid::Uuid;

pub const LOGIN_TIMEOUT: Duration = Duration::from_mins(2);
pub const API_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const CALLBACK_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CALLBACK_BYTES: usize = 8192;

#[derive(Parser, Debug)]
#[command(name = "rotation-control", version, disable_help_subcommand = true)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Login(AuthArgs),
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Rotate(RotateArgs),
    Status(StatusArgs),
    Audit(AuditArgs),
}

#[derive(Subcommand, Debug)]
enum PolicyCommand {
    Check(PolicyCheckArgs),
}

#[derive(Args, Clone, Debug)]
struct AuthArgs {
    #[arg(long)]
    issuer: Url,
    #[arg(long, default_value = "rotation-control")]
    client_id: String,
    #[arg(long)]
    tenant_id: String,
    #[arg(long, default_value = "http://127.0.0.1:8765/callback")]
    redirect_uri: Url,
    #[arg(long)]
    ca_certificate: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct PolicyCheckArgs {
    #[arg(long)]
    input: PathBuf,
}

#[derive(Args, Debug)]
struct RotateArgs {
    #[command(flatten)]
    auth: AuthArgs,
    #[arg(long)]
    rss_base_url: Url,
    #[arg(long)]
    device_id: Uuid,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    expected_generation: u64,
    #[arg(long)]
    idempotency_key: Option<Uuid>,
}

#[derive(Args, Debug)]
struct StatusArgs {
    #[command(flatten)]
    auth: AuthArgs,
    #[arg(long)]
    rss_base_url: Url,
    #[arg(long)]
    device_id: Uuid,
}

#[derive(Args, Debug)]
struct AuditArgs {
    #[arg(long)]
    input: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyInput {
    key_usages: Vec<UsageInput>,
    renew_before_seconds: u64,
    #[serde(default)]
    sans: Vec<String>,
    validity_seconds: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum UsageInput {
    ClientAuth,
    ServerAuth,
}

impl TryFrom<PolicyInput> for RotationPolicy {
    type Error = AppError;
    fn try_from(value: PolicyInput) -> Result<Self, Self::Error> {
        let usages = value
            .key_usages
            .into_iter()
            .map(|usage| match usage {
                UsageInput::ClientAuth => KeyUsage::ClientAuth,
                UsageInput::ServerAuth => KeyUsage::ServerAuth,
            })
            .collect();
        RotationPolicy::try_new(
            usages,
            value.renew_before_seconds,
            value.sans,
            value.validity_seconds,
        )
        .map_err(|_| AppError::input("invalid_policy"))
    }
}

#[derive(Clone)]
struct TokenSet {
    access_token: String,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TokenSet([REDACTED])")
    }
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct TokenWire {
    access_token: String,
    id_token: RotationIdToken,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TenantClaims {
    #[serde(rename = "tenantId")]
    tenant_id: String,
}
impl AdditionalClaims for TenantClaims {}

type RotationIdToken = IdToken<
    TenantClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

const CALLBACK_INVALID: &str = "callback_invalid";
const INVALID_DISCOVERY: &str = "invalid_discovery";
const INPUT_UNREADABLE: &str = "input_unreadable";
const RESPONSE_OVERSIZE: &str = "response_oversize";

#[derive(Debug)]
pub struct AppError {
    code: &'static str,
    class: ErrorClass,
    stage: ErrorStage,
    request_id: Option<String>,
    retryable: bool,
}

#[derive(Clone, Copy, Debug)]
enum ErrorClass {
    Input,
    Auth,
    Typed,
    Transport,
    Untrusted,
}

#[derive(Clone, Copy, Debug)]
enum ErrorStage {
    Input,
    Runtime,
    Discovery,
    Callback,
    TokenExchange,
    Jwks,
    IdToken,
    Api,
    Transport,
}

impl ErrorStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Runtime => "runtime",
            Self::Discovery => "discovery",
            Self::Callback => "callback",
            Self::TokenExchange => "token_exchange",
            Self::Jwks => "jwks",
            Self::IdToken => "id_token",
            Self::Api => "api",
            Self::Transport => "transport",
        }
    }
}

impl AppError {
    fn input(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Input,
            stage: ErrorStage::Input,
            request_id: None,
            retryable: false,
        }
    }
    fn auth(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Auth,
            stage: ErrorStage::IdToken,
            request_id: None,
            retryable: false,
        }
    }
    fn transport(code: &'static str, retryable: bool) -> Self {
        Self {
            code,
            class: ErrorClass::Transport,
            stage: ErrorStage::Transport,
            request_id: None,
            retryable,
        }
    }
    fn untrusted(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Untrusted,
            stage: ErrorStage::Transport,
            request_id: None,
            retryable: false,
        }
    }
    fn from_diagnostic(value: &Diagnostic) -> Self {
        let class = match value.kind() {
            DiagnosticKind::Unauthorized | DiagnosticKind::Forbidden => ErrorClass::Auth,
            DiagnosticKind::Validation | DiagnosticKind::NotFound | DiagnosticKind::Conflict => {
                ErrorClass::Typed
            }
            DiagnosticKind::RateLimited | DiagnosticKind::Upstream => ErrorClass::Transport,
            DiagnosticKind::Malformed | DiagnosticKind::UnknownStatus => ErrorClass::Untrusted,
        };
        Self {
            code: value.kind().code(),
            class,
            stage: ErrorStage::Api,
            request_id: value.request_id().map(ToOwned::to_owned),
            retryable: value.retryable(),
        }
    }
    fn at(mut self, stage: ErrorStage) -> Self {
        self.stage = stage;
        self
    }
    fn exit_code(&self) -> i32 {
        match self.class {
            ErrorClass::Input => 2,
            ErrorClass::Auth => 3,
            ErrorClass::Typed => 4,
            ErrorClass::Transport => 5,
            ErrorClass::Untrusted => 6,
        }
    }
    fn render(&self) -> Value {
        json!({"schemaVersion":"1","outcome":"error","diagnostic":{"category":match self.class { ErrorClass::Input => "input", ErrorClass::Auth => "auth", ErrorClass::Typed => "typed", ErrorClass::Transport => "transport", ErrorClass::Untrusted => "untrusted" },"stage":self.stage.as_str(),"code":self.code,"retryable":self.retryable,"requestId":self.request_id}})
    }
}

#[must_use]
pub fn main_entry() -> i32 {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                println!(
                    "{}",
                    json!({"schemaVersion":"1","operation":if error.kind() == ErrorKind::DisplayHelp { "help" } else { "version" },"outcome":"success","text":error.to_string()})
                );
                return 0;
            }
            println!(
                "{}",
                AppError::input(if error.use_stderr() {
                    "invalid_cli"
                } else {
                    "cli_help"
                })
                .render()
            );
            return 2;
        }
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        println!(
            "{}",
            AppError::transport("runtime_unavailable", false)
                .at(ErrorStage::Runtime)
                .render()
        );
        return 5;
    };
    match runtime.block_on(run(cli)) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            println!("{}", error.render());
            error.exit_code()
        }
    }
}

async fn run(cli: Cli) -> Result<Value, AppError> {
    match cli.command {
        Command::Login(auth) => {
            let _ = login(&auth).await?;
            Ok(
                json!({"schemaVersion":"1","operation":"login","outcome":"authenticated","tokenPersisted":false}),
            )
        }
        Command::Policy {
            command: PolicyCommand::Check(args),
        } => {
            let policy = read_policy(&args.input)?;
            Ok(
                json!({"schemaVersion":"1","operation":"policy.check","outcome":"valid","validitySeconds":policy.validity_seconds(),"renewBeforeSeconds":policy.renew_before_seconds(),"keyUsageCount":policy.key_usages().len(),"sanCount":policy.sans().len()}),
            )
        }
        Command::Rotate(args) => rotate(args).await,
        Command::Status(args) => status(args).await,
        Command::Audit(args) => audit(&args.input),
    }
}

fn read_policy(path: &PathBuf) -> Result<RotationPolicy, AppError> {
    let bytes = fs::read(path).map_err(|_| AppError::input(INPUT_UNREADABLE))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AppError::input("input_oversize"));
    }
    let input: PolicyInput =
        serde_json::from_slice(&bytes).map_err(|_| AppError::input("invalid_policy_json"))?;
    input.try_into()
}

fn secure_remote_url(url: &Url, allow_loopback_http: bool) -> Result<(), AppError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() == "http" && allow_loopback_http && loopback {
        Ok(())
    } else {
        Err(AppError::input("plaintext_remote_forbidden"))
    }
}

fn validate_rss_base_url(url: &Url) -> Result<(), AppError> {
    secure_remote_url(url, false)?;
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(AppError::input("rss_base_url_must_be_origin"));
    }
    Ok(())
}

struct HttpReply {
    status: u16,
    body: Vec<u8>,
}

#[async_trait]
trait HttpPort: Send + Sync {
    async fn get(&self, url: Url, limit: Duration) -> Result<HttpReply, AppError>;
    async fn post_form(
        &self,
        url: Url,
        form: Vec<(String, String)>,
        limit: Duration,
    ) -> Result<HttpReply, AppError>;
    async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        limit: Duration,
    ) -> Result<HttpReply, AppError>;
}

trait BrowserPort: Send + Sync {
    fn open(&self, url: &Url) -> Result<(), AppError>;
}
trait ClockPort: Send + Sync {
    fn unix_seconds(&self) -> Result<u64, AppError>;
}
trait IdTokenVerifierPort: Send + Sync {
    fn verify(
        &self,
        token: &RotationIdToken,
        jwks: &CoreJsonWebKeySet,
        auth: &AuthArgs,
        nonce: &str,
        now: u64,
    ) -> Result<(), AppError>;
}

#[async_trait]
trait CallbackPort: Send + Sync {
    async fn authorize(
        &self,
        redirect: &Url,
        state: &str,
        authorize: &Url,
        browser: &dyn BrowserPort,
    ) -> Result<String, AppError>;
}

struct SystemBrowser;
impl BrowserPort for SystemBrowser {
    fn open(&self, url: &Url) -> Result<(), AppError> {
        webbrowser::open(url.as_str())
            .map_err(|_| AppError::auth("browser_launch_failed").at(ErrorStage::Callback))
    }
}

struct SystemClock;
impl ClockPort for SystemClock {
    fn unix_seconds(&self) -> Result<u64, AppError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AppError::auth("clock_invalid"))
            .map(|value| value.as_secs())
    }
}
struct Rs256IdTokenVerifier;
impl IdTokenVerifierPort for Rs256IdTokenVerifier {
    fn verify(
        &self,
        token: &RotationIdToken,
        jwks: &CoreJsonWebKeySet,
        auth: &AuthArgs,
        nonce: &str,
        now: u64,
    ) -> Result<(), AppError> {
        validate_id_token(token, jwks, auth, nonce, now)
    }
}

struct LoopbackCallback;
#[async_trait]
impl CallbackPort for LoopbackCallback {
    async fn authorize(
        &self,
        redirect: &Url,
        state: &str,
        authorize: &Url,
        browser: &dyn BrowserPort,
    ) -> Result<String, AppError> {
        let host = redirect
            .host_str()
            .ok_or_else(|| AppError::input("invalid_redirect"))?;
        let listener = TcpListener::bind((
            host,
            redirect
                .port_or_known_default()
                .ok_or_else(|| AppError::input("invalid_redirect"))?,
        ))
        .await
        .map_err(|_| AppError::auth("callback_bind_failed").at(ErrorStage::Callback))?;
        browser.open(authorize)?;
        receive_callback(listener, redirect, state).await
    }
}

struct ReqwestHttpPort {
    client: Client,
}
impl ReqwestHttpPort {
    fn new(ca_certificate: Option<&PathBuf>) -> Result<Self, AppError> {
        let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(path) = ca_certificate {
            let bytes = fs::read(path).map_err(|_| AppError::input(INPUT_UNREADABLE))?;
            if bytes.len() > MAX_RESPONSE_BYTES {
                return Err(AppError::input("ca_certificate_oversize"));
            }
            let certificate = reqwest::Certificate::from_pem(&bytes)
                .map_err(|_| AppError::input("invalid_ca_certificate"))?;
            builder = builder.add_root_certificate(certificate);
        }
        builder
            .build()
            .map(|client| Self { client })
            .map_err(|_| AppError::transport("http_client_unavailable", false))
    }

    async fn execute(
        &self,
        request: reqwest::RequestBuilder,
        limit: Duration,
    ) -> Result<HttpReply, AppError> {
        timeout(limit, async {
            let response = request
                .send()
                .await
                .map_err(|_| AppError::transport("request_failed", true))?;
            let status = response.status().as_u16();
            let body = bounded_bytes(response).await?;
            Ok(HttpReply { status, body })
        })
        .await
        .map_err(|_| AppError::transport("request_timeout", true))?
    }
}

#[async_trait]
impl HttpPort for ReqwestHttpPort {
    async fn get(&self, url: Url, limit: Duration) -> Result<HttpReply, AppError> {
        self.execute(self.client.get(url), limit).await
    }
    async fn post_form(
        &self,
        url: Url,
        form: Vec<(String, String)>,
        limit: Duration,
    ) -> Result<HttpReply, AppError> {
        self.execute(self.client.post(url).form(&form), limit).await
    }
    async fn send(
        &self,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
        limit: Duration,
    ) -> Result<HttpReply, AppError> {
        let mut request = self.client.request(method, url).headers(headers);
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        self.execute(request, limit).await
    }
}

fn discovery_url(issuer: &Url) -> Result<Url, AppError> {
    let mut value = issuer.clone();
    let path = format!("{}/", value.path().trim_end_matches('/'));
    value.set_path(&path);
    value
        .join(".well-known/openid-configuration")
        .map_err(|_| AppError::input("invalid_issuer"))
}

async fn login(auth: &AuthArgs) -> Result<TokenSet, AppError> {
    let http = ReqwestHttpPort::new(auth.ca_certificate.as_ref())?;
    authenticate(
        auth,
        &http,
        &SystemBrowser,
        &SystemClock,
        &LoopbackCallback,
        &Rs256IdTokenVerifier,
    )
    .await
}

async fn authenticate(
    auth: &AuthArgs,
    http: &dyn HttpPort,
    browser: &dyn BrowserPort,
    clock: &dyn ClockPort,
    callback: &dyn CallbackPort,
    verifier: &dyn IdTokenVerifierPort,
) -> Result<TokenSet, AppError> {
    authenticate_with_limit(
        auth,
        http,
        browser,
        clock,
        callback,
        verifier,
        LOGIN_TIMEOUT,
    )
    .await
}

async fn authenticate_with_limit(
    auth: &AuthArgs,
    http: &dyn HttpPort,
    browser: &dyn BrowserPort,
    clock: &dyn ClockPort,
    callback: &dyn CallbackPort,
    verifier: &dyn IdTokenVerifierPort,
    limit: Duration,
) -> Result<TokenSet, AppError> {
    authenticate_inner(
        auth,
        http,
        browser,
        clock,
        callback,
        verifier,
        Instant::now() + limit,
    )
    .await
}

async fn authenticate_inner(
    auth: &AuthArgs,
    http: &dyn HttpPort,
    browser: &dyn BrowserPort,
    clock: &dyn ClockPort,
    callback: &dyn CallbackPort,
    verifier: &dyn IdTokenVerifierPort,
    deadline: Instant,
) -> Result<TokenSet, AppError> {
    secure_remote_url(&auth.issuer, false)?;
    secure_remote_url(&auth.redirect_uri, true)?;
    let callback_host = auth
        .redirect_uri
        .host_str()
        .ok_or_else(|| AppError::input("invalid_redirect"))?;
    if callback_host
        .parse::<IpAddr>()
        .ok()
        .is_none_or(|ip| !ip.is_loopback())
    {
        return Err(AppError::input("redirect_not_loopback"));
    }
    let discovery: Discovery = within_login_deadline(
        deadline,
        ErrorStage::Discovery,
        fetch_json(
            http,
            discovery_url(&auth.issuer)?,
            LOGIN_TIMEOUT,
            ErrorStage::Discovery,
        ),
    )
    .await?;
    if discovery.issuer != auth.issuer.as_str() {
        return Err(AppError::auth("issuer_mismatch").at(ErrorStage::Discovery));
    }
    let authorization_endpoint = Url::parse(&discovery.authorization_endpoint)
        .map_err(|_| AppError::untrusted(INVALID_DISCOVERY).at(ErrorStage::Discovery))?;
    let token_endpoint = Url::parse(&discovery.token_endpoint)
        .map_err(|_| AppError::untrusted(INVALID_DISCOVERY).at(ErrorStage::Discovery))?;
    let jwks_uri = Url::parse(&discovery.jwks_uri)
        .map_err(|_| AppError::untrusted(INVALID_DISCOVERY).at(ErrorStage::Discovery))?;
    secure_remote_url(&authorization_endpoint, false)?;
    secure_remote_url(&token_endpoint, false)?;
    secure_remote_url(&jwks_uri, false)?;
    let state = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let (challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorize = authorization_endpoint;
    authorize
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &auth.client_id)
        .append_pair("redirect_uri", auth.redirect_uri.as_str())
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", challenge.as_str())
        .append_pair("code_challenge_method", "S256");
    let code = within_login_deadline(
        deadline,
        ErrorStage::Callback,
        callback.authorize(&auth.redirect_uri, &state, &authorize, browser),
    )
    .await?;
    let response = within_login_deadline(
        deadline,
        ErrorStage::TokenExchange,
        http.post_form(
            token_endpoint,
            vec![
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("code".to_owned(), code),
                ("redirect_uri".to_owned(), auth.redirect_uri.to_string()),
                ("client_id".to_owned(), auth.client_id.clone()),
                (
                    "code_verifier".to_owned(),
                    pkce_verifier.secret().to_owned(),
                ),
            ],
            LOGIN_TIMEOUT,
        ),
    )
    .await?;
    classify_token_response(response.status)?;
    let token: TokenWire = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::untrusted("malformed_json").at(ErrorStage::TokenExchange))?;
    let jwks =
        within_login_deadline(deadline, ErrorStage::Jwks, fetch_jwks(http, jwks_uri)).await?;
    verifier.verify(&token.id_token, &jwks, auth, &nonce, clock.unix_seconds()?)?;
    Ok(TokenSet {
        access_token: token.access_token,
    })
}

async fn within_login_deadline<T, F>(
    deadline: Instant,
    stage: ErrorStage,
    future: F,
) -> Result<T, AppError>
where
    F: Future<Output = Result<T, AppError>>,
{
    timeout_at(deadline, future)
        .await
        .map_err(|_| AppError::auth("login_timeout").at(stage))?
        .map_err(|error| error.at(stage))
}

fn classify_token_response(status: u16) -> Result<(), AppError> {
    match status {
        200 => Ok(()),
        400 | 401 | 403 => {
            Err(AppError::auth("token_exchange_rejected").at(ErrorStage::TokenExchange))
        }
        429 | 500..=599 => {
            Err(AppError::transport("token_upstream_rejected", true).at(ErrorStage::TokenExchange))
        }
        _ => Err(AppError::untrusted("token_status_unknown").at(ErrorStage::TokenExchange)),
    }
}

async fn receive_callback(
    listener: TcpListener,
    redirect: &Url,
    expected_state: &str,
) -> Result<String, AppError> {
    loop {
        let (mut socket, _) = listener
            .accept()
            .await
            .map_err(|_| AppError::auth("callback_failed").at(ErrorStage::Callback))?;
        let outcome = read_callback_headers(&mut socket)
            .await
            .ok()
            .and_then(|request| parse_callback_request(&request, redirect, expected_state));
        match outcome {
            Some(CallbackOutcome::Code(code)) => {
                write_callback_page(&mut socket, "200 OK", "Authentication complete.").await;
                return Ok(code);
            }
            Some(CallbackOutcome::Rejected) => {
                write_callback_page(&mut socket, "400 Bad Request", "Authentication rejected.")
                    .await;
                return Err(AppError::auth("authorization_rejected").at(ErrorStage::Callback));
            }
            None => {
                write_callback_page(&mut socket, "400 Bad Request", "Authentication ignored.")
                    .await;
            }
        }
    }
}

enum CallbackOutcome {
    Code(String),
    Rejected,
}

async fn read_callback_headers(socket: &mut tokio::net::TcpStream) -> Result<Vec<u8>, AppError> {
    timeout_at(Instant::now() + CALLBACK_CONNECTION_TIMEOUT, async {
        let mut request = Vec::new();
        while request.len() < MAX_CALLBACK_BYTES {
            let remaining = MAX_CALLBACK_BYTES - request.len();
            let mut chunk = vec![0_u8; remaining.min(1024)];
            let count = socket
                .read(&mut chunk)
                .await
                .map_err(|_| AppError::auth("callback_failed").at(ErrorStage::Callback))?;
            if count == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..count]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(request);
            }
        }
        Err(AppError::auth(CALLBACK_INVALID).at(ErrorStage::Callback))
    })
    .await
    .map_err(|_| AppError::auth("callback_connection_timeout").at(ErrorStage::Callback))?
}

fn parse_callback_request(
    request: &[u8],
    redirect: &Url,
    expected_state: &str,
) -> Option<CallbackOutcome> {
    let first = std::str::from_utf8(request).ok()?.split("\r\n").next()?;
    let mut parts = first.split_whitespace();
    if parts.next()? != "GET" {
        return None;
    }
    let target = parts.next()?;
    if parts.next()? != "HTTP/1.1"
        || parts.next().is_some()
        || !target.starts_with('/')
        || target.starts_with("//")
    {
        return None;
    }
    let callback = redirect.join(target).ok()?;
    if callback.scheme() != redirect.scheme()
        || callback.host_str() != redirect.host_str()
        || callback.port_or_known_default() != redirect.port_or_known_default()
        || callback.path() != redirect.path()
        || callback.fragment().is_some()
    {
        return None;
    }
    let mut states = callback
        .query_pairs()
        .filter(|(key, _)| key == "state")
        .map(|(_, value)| value);
    if states.next().as_deref() != Some(expected_state) || states.next().is_some() {
        return None;
    }
    if callback.query_pairs().any(|(key, _)| key == "error") {
        return Some(CallbackOutcome::Rejected);
    }
    let mut codes = callback
        .query_pairs()
        .filter(|(key, _)| key == "code")
        .map(|(_, value)| value);
    let code = codes.next()?.to_string();
    if code.is_empty() || codes.next().is_some() {
        return None;
    }
    Some(CallbackOutcome::Code(code))
}

async fn write_callback_page(socket: &mut tokio::net::TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(response.as_bytes()).await;
}

fn validate_id_token(
    token: &RotationIdToken,
    jwks: &CoreJsonWebKeySet,
    auth: &AuthArgs,
    nonce: &str,
    now: u64,
) -> Result<(), AppError> {
    let now = i64::try_from(now)
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .ok_or_else(|| AppError::auth("clock_invalid"))?;
    let verifier = CoreIdTokenVerifier::new_public_client(
        ClientId::new(auth.client_id.clone()),
        IssuerUrl::new(auth.issuer.to_string()).map_err(|_| AppError::auth("issuer_invalid"))?,
        jwks.clone(),
    )
    .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
    .set_other_audience_verifier_fn(|_| true)
    .set_time_fn(move || now)
    .set_issue_time_verifier_fn(move |issued_at| {
        (issued_at <= now)
            .then_some(())
            .ok_or_else(|| "ID token issue time is in the future".to_owned())
    });
    let claims = token
        .claims(&verifier, &Nonce::new(nonce.to_owned()))
        .map_err(|_| AppError::auth("id_token_invalid"))?;
    let client_id = ClientId::new(auth.client_id.clone());
    if claims.audiences().len() > 1 && claims.authorized_party() != Some(&client_id) {
        return Err(AppError::auth("authorized_party_mismatch"));
    }
    if claims
        .authorized_party()
        .is_some_and(|authorized_party| authorized_party != &client_id)
    {
        return Err(AppError::auth("authorized_party_mismatch"));
    }
    if claims.additional_claims().tenant_id != auth.tenant_id {
        return Err(AppError::auth("tenant_mismatch"));
    }
    Ok(())
}

async fn rotate(args: RotateArgs) -> Result<Value, AppError> {
    let http = ReqwestHttpPort::new(args.auth.ca_certificate.as_ref())?;
    rotate_with_ports(
        args,
        &http,
        &SystemBrowser,
        &SystemClock,
        &LoopbackCallback,
        &Rs256IdTokenVerifier,
    )
    .await
}

async fn rotate_with_ports(
    args: RotateArgs,
    http: &dyn HttpPort,
    browser: &dyn BrowserPort,
    clock: &dyn ClockPort,
    callback: &dyn CallbackPort,
    verifier: &dyn IdTokenVerifierPort,
) -> Result<Value, AppError> {
    validate_rss_base_url(&args.rss_base_url)?;
    let policy = read_policy(&args.input)?;
    let token = authenticate(&args.auth, http, browser, clock, callback, verifier).await?;
    let request_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let prepared = prepare_policy_put(
        args.device_id,
        args.expected_generation,
        args.idempotency_key.unwrap_or_else(Uuid::new_v4),
        &policy,
    )
    .map_err(|_| AppError::input("invalid_policy"))?;
    let response = send_api(
        &args.rss_base_url,
        &prepared,
        &token,
        &args.auth.tenant_id,
        request_id,
        correlation_id,
        http,
    )
    .await?;
    match decode_policy_response(response.0, &response.1) {
        PolicyResponse::Accepted(value) => Ok(
            json!({"schemaVersion":"1","operation":"rotate","outcome":"accepted","requestId":request_id,"correlationId":correlation_id,"authorizationReceiptId":value.receipt_id(),"acceptedGeneration":value.generation(),"condition":value.condition().as_str()}),
        ),
        PolicyResponse::Rejected(error) => Err(AppError::from_diagnostic(&error)),
    }
}

async fn status(args: StatusArgs) -> Result<Value, AppError> {
    let http = ReqwestHttpPort::new(args.auth.ca_certificate.as_ref())?;
    status_with_ports(
        args,
        &http,
        &SystemBrowser,
        &SystemClock,
        &LoopbackCallback,
        &Rs256IdTokenVerifier,
    )
    .await
}

async fn status_with_ports(
    args: StatusArgs,
    http: &dyn HttpPort,
    browser: &dyn BrowserPort,
    clock: &dyn ClockPort,
    callback: &dyn CallbackPort,
    verifier: &dyn IdTokenVerifierPort,
) -> Result<Value, AppError> {
    validate_rss_base_url(&args.rss_base_url)?;
    let token = authenticate(&args.auth, http, browser, clock, callback, verifier).await?;
    let request_id = Uuid::new_v4();
    let correlation_id = Uuid::new_v4();
    let prepared = prepare_status_get(args.device_id);
    let response = send_api(
        &args.rss_base_url,
        &prepared,
        &token,
        &args.auth.tenant_id,
        request_id,
        correlation_id,
        http,
    )
    .await?;
    match decode_status_response(response.0, &response.1) {
        StatusResponse::Observed(value) => Ok(
            json!({"schemaVersion":"1","operation":"status","outcome":"observed","requestId":request_id,"correlationId":correlation_id,"desiredGeneration":value.desired_generation(),"authorizationReceiptId":value.authorization_receipt_id(),"observedGeneration":value.observed_generation(),"activeCommand":value.active_command().map(|item| json!({"fenceEpoch":item.fence_epoch(),"state":item.state().as_str()})),"conditions":value.conditions().iter().map(|item| json!({"observedGeneration":item.observed_generation(),"reason":item.reason().as_str(),"status":item.status().as_str(),"type":item.type_().as_str(),"lastTransitionAt":item.last_transition_at()})).collect::<Vec<_>>() }),
        ),
        StatusResponse::Rejected(error) => Err(AppError::from_diagnostic(&error)),
    }
}

async fn send_api(
    base: &Url,
    prepared: &rss_device_security_client::PreparedRequest,
    token: &TokenSet,
    tenant: &str,
    request_id: Uuid,
    correlation_id: Uuid,
    http: &dyn HttpPort,
) -> Result<(u16, Vec<u8>), AppError> {
    let url = base
        .join(prepared.path())
        .map_err(|_| AppError::input("invalid_rss_url"))?;
    let method = Method::from_bytes(prepared.method().as_bytes())
        .map_err(|_| AppError::untrusted("invalid_operation"))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token.access_token))
            .map_err(|_| AppError::auth("token_invalid"))?,
    );
    headers.insert(
        "x-tenant-id",
        HeaderValue::from_str(tenant).map_err(|_| AppError::input("invalid_tenant"))?,
    );
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("UUID header"),
    );
    headers.insert(
        "x-correlation-id",
        HeaderValue::from_str(&correlation_id.to_string()).expect("UUID header"),
    );
    let response = http
        .send(
            method,
            url,
            headers,
            prepared.body().map(<[u8]>::to_vec),
            API_TIMEOUT,
        )
        .await
        .map_err(|error| error.at(ErrorStage::Api))?;
    Ok((response.status, response.body))
}

async fn bounded_bytes(response: reqwest::Response) -> Result<Vec<u8>, AppError> {
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(AppError::untrusted(RESPONSE_OVERSIZE));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AppError::transport("response_read_failed", true))?;
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(AppError::untrusted(RESPONSE_OVERSIZE));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn fetch_json<T: for<'de> Deserialize<'de>>(
    http: &dyn HttpPort,
    url: Url,
    limit: Duration,
    stage: ErrorStage,
) -> Result<T, AppError> {
    let response = http
        .get(url, limit)
        .await
        .map_err(|error| error.at(stage))?;
    if response.status != StatusCode::OK.as_u16() {
        return Err(AppError::transport("upstream_rejected", false).at(stage));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| AppError::untrusted("malformed_json").at(stage))
}

async fn fetch_jwks(http: &dyn HttpPort, url: Url) -> Result<CoreJsonWebKeySet, AppError> {
    let response = http
        .get(url, LOGIN_TIMEOUT)
        .await
        .map_err(|error| error.at(ErrorStage::Jwks))?;
    if response.status != StatusCode::OK.as_u16() {
        return Err(AppError::transport("upstream_rejected", false).at(ErrorStage::Jwks));
    }
    validate_jwks_key_operations(&response.body)?;
    serde_json::from_slice(&response.body)
        .map_err(|_| AppError::untrusted("malformed_json").at(ErrorStage::Jwks))
}

fn validate_jwks_key_operations(body: &[u8]) -> Result<(), AppError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| AppError::untrusted("malformed_json").at(ErrorStage::Jwks))?;
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| AppError::untrusted("malformed_json").at(ErrorStage::Jwks))?;
    for key in keys {
        if let Some(operations) = key.get("key_ops") {
            let Some(operations) = operations.as_array() else {
                return Err(AppError::auth("id_token_key_usage").at(ErrorStage::Jwks));
            };
            if operations.len() != 1 || operations[0].as_str() != Some("verify") {
                return Err(AppError::auth("id_token_key_usage").at(ErrorStage::Jwks));
            }
        }
    }
    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RotateRecord {
    schema_version: String,
    operation: String,
    outcome: String,
    request_id: Uuid,
    correlation_id: Uuid,
    authorization_receipt_id: Uuid,
    accepted_generation: u64,
    condition: String,
}

fn audit(input: &str) -> Result<Value, AppError> {
    let mut bytes = Vec::new();
    if input == "-" {
        io::stdin()
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| AppError::input(INPUT_UNREADABLE))?;
    } else {
        bytes = fs::read(input).map_err(|_| AppError::input(INPUT_UNREADABLE))?;
    }
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(AppError::input("input_oversize"));
    }
    let record: RotateRecord =
        serde_json::from_slice(&bytes).map_err(|_| AppError::input("invalid_rotate_record"))?;
    if record.schema_version != "1"
        || record.operation != "rotate"
        || record.outcome != "accepted"
        || record.accepted_generation == 0
        || !matches!(record.condition.as_str(), "Reconciling" | "PendingDevice")
    {
        return Err(AppError::input("invalid_rotate_record"));
    }
    Ok(
        json!({"schemaVersion":"1","operation":"audit","outcome":"validated","requestId":record.request_id,"correlationId":record.correlation_id,"authorizationReceiptId":record.authorization_receipt_id,"acceptedGeneration":record.accepted_generation,"durableAuditQueried":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::{
        Audience, IdTokenClaims, JsonWebKeyId, PrivateSigningKey, StandardClaims,
        SubjectIdentifier, core::CoreRsaPrivateSigningKey,
    };
    use rand::thread_rng;
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding};
    use std::{
        collections::VecDeque,
        sync::{Mutex, OnceLock},
    };
    use tempfile::tempdir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method, path},
    };

    fn auth() -> AuthArgs {
        AuthArgs {
            issuer: Url::parse("https://issuer.example/").expect("issuer"),
            client_id: "client".to_owned(),
            tenant_id: "tenant".to_owned(),
            redirect_uri: Url::parse("http://127.0.0.1:8765/callback").expect("redirect"),
            ca_certificate: None,
        }
    }

    fn signed_token(
        audiences: Vec<Audience>,
        authorized_party: Option<ClientId>,
        tenant: &str,
    ) -> (RotationIdToken, CoreJsonWebKeySet) {
        static TEST_RSA_PEM: OnceLock<String> = OnceLock::new();
        let pem = TEST_RSA_PEM.get_or_init(|| {
            RsaPrivateKey::new(&mut thread_rng(), 2_048)
                .expect("ephemeral test key")
                .to_pkcs1_pem(LineEnding::LF)
                .expect("encode test key")
                .to_string()
        });
        let key =
            CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new("test-key".to_owned())))
                .expect("test key");
        let claims = IdTokenClaims::new(
            IssuerUrl::new("https://issuer.example/".to_owned()).expect("issuer"),
            audiences,
            DateTime::from_timestamp(2_000, 0).expect("expiry"),
            DateTime::from_timestamp(900, 0).expect("issued"),
            StandardClaims::new(SubjectIdentifier::new("subject".to_owned())),
            TenantClaims {
                tenant_id: tenant.to_owned(),
            },
        )
        .set_nonce(Some(Nonce::new("nonce".to_owned())))
        .set_authorized_party(authorized_party);
        let token = RotationIdToken::new(
            claims,
            &key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("token");
        (
            token,
            CoreJsonWebKeySet::new(vec![key.as_verification_key()]),
        )
    }

    struct FakeBrowser;
    impl BrowserPort for FakeBrowser {
        fn open(&self, _: &Url) -> Result<(), AppError> {
            Ok(())
        }
    }
    struct FakeClock;
    impl ClockPort for FakeClock {
        fn unix_seconds(&self) -> Result<u64, AppError> {
            Ok(1_000)
        }
    }
    struct FakeCallback;
    #[async_trait]
    impl CallbackPort for FakeCallback {
        async fn authorize(
            &self,
            _: &Url,
            _: &str,
            authorize: &Url,
            _: &dyn BrowserPort,
        ) -> Result<String, AppError> {
            let query = authorize
                .query_pairs()
                .collect::<std::collections::HashMap<_, _>>();
            assert_eq!(
                query
                    .get("code_challenge_method")
                    .map(std::convert::AsRef::as_ref),
                Some("S256")
            );
            assert!(query.contains_key("state"));
            assert!(query.contains_key("nonce"));
            Ok("authorization-code".to_owned())
        }
    }
    struct FakeVerifier;
    impl IdTokenVerifierPort for FakeVerifier {
        fn verify(
            &self,
            _: &RotationIdToken,
            _: &CoreJsonWebKeySet,
            _: &AuthArgs,
            _: &str,
            now: u64,
        ) -> Result<(), AppError> {
            assert_eq!(now, 1_000);
            Ok(())
        }
    }
    type RecordedRequest = (Method, Url, HeaderMap, Option<Vec<u8>>);
    struct FakeHttp {
        replies: Mutex<VecDeque<Result<HttpReply, AppError>>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }
    impl FakeHttp {
        fn new(replies: Vec<Result<HttpReply, AppError>>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
        fn next(&self) -> Result<HttpReply, AppError> {
            self.replies
                .lock()
                .expect("replies")
                .pop_front()
                .expect("fake reply")
        }
    }
    #[async_trait]
    impl HttpPort for FakeHttp {
        async fn get(&self, _: Url, _: Duration) -> Result<HttpReply, AppError> {
            self.next()
        }
        async fn post_form(
            &self,
            _: Url,
            form: Vec<(String, String)>,
            _: Duration,
        ) -> Result<HttpReply, AppError> {
            assert!(form.iter().any(|(key, _)| key == "code_verifier"));
            self.next()
        }
        async fn send(
            &self,
            method: Method,
            url: Url,
            headers: HeaderMap,
            body: Option<Vec<u8>>,
            _: Duration,
        ) -> Result<HttpReply, AppError> {
            self.requests
                .lock()
                .expect("requests")
                .push((method, url, headers, body));
            self.next()
        }
    }
    struct DelayedHttp {
        inner: FakeHttp,
        delay: Duration,
    }
    #[async_trait]
    impl HttpPort for DelayedHttp {
        async fn get(&self, url: Url, limit: Duration) -> Result<HttpReply, AppError> {
            tokio::time::sleep(self.delay).await;
            self.inner.get(url, limit).await
        }
        async fn post_form(
            &self,
            url: Url,
            form: Vec<(String, String)>,
            limit: Duration,
        ) -> Result<HttpReply, AppError> {
            tokio::time::sleep(self.delay).await;
            self.inner.post_form(url, form, limit).await
        }
        async fn send(
            &self,
            method: Method,
            url: Url,
            headers: HeaderMap,
            body: Option<Vec<u8>>,
            limit: Duration,
        ) -> Result<HttpReply, AppError> {
            tokio::time::sleep(self.delay).await;
            self.inner.send(method, url, headers, body, limit).await
        }
    }
    fn reply(status: u16, body: &Value) -> HttpReply {
        HttpReply {
            status,
            body: serde_json::to_vec(body).expect("body"),
        }
    }
    fn auth_replies(api_status: u16, api_body: &Value) -> Vec<Result<HttpReply, AppError>> {
        let (id_token, _) = signed_token(vec![Audience::new("client".to_owned())], None, "tenant");
        vec![
            Ok(reply(
                200,
                &json!({"issuer":"https://issuer.example/","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
            )),
            Ok(reply(
                200,
                &json!({"access_token":"token-bait","id_token":id_token}),
            )),
            Ok(reply(200, &json!({"keys":[]}))),
            Ok(reply(api_status, api_body)),
        ]
    }
    fn rotate_args(input: PathBuf) -> RotateArgs {
        RotateArgs {
            auth: auth(),
            rss_base_url: Url::parse("https://rss.example/").expect("rss"),
            device_id: Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678901").expect("device"),
            input,
            expected_generation: 4,
            idempotency_key: Some(
                Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678902").expect("key"),
            ),
        }
    }
    fn status_args() -> StatusArgs {
        StatusArgs {
            auth: auth(),
            rss_base_url: Url::parse("https://rss.example/").expect("rss"),
            device_id: Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678901").expect("device"),
        }
    }
    fn policy_file() -> (tempfile::TempDir, PathBuf) {
        let directory = tempdir().expect("temp");
        let path = directory.path().join("policy.json");
        fs::write(
            &path,
            r#"{"keyUsages":["clientAuth"],"renewBeforeSeconds":600,"validitySeconds":3600}"#,
        )
        .expect("policy");
        (directory, path)
    }

    #[test]
    fn typed_verifier_rejects_audience_nonce_expiry_tenant_and_authorized_party() {
        let (token, jwks) = signed_token(vec![Audience::new("client".to_owned())], None, "tenant");
        assert!(validate_id_token(&token, &jwks, &auth(), "nonce", 1_000).is_ok());
        for (configured, nonce, now, expected) in [
            (
                {
                    let mut value = auth();
                    value.client_id = "other".to_owned();
                    value
                },
                "nonce",
                1_000,
                "id_token_invalid",
            ),
            (auth(), "wrong", 1_000, "id_token_invalid"),
            (auth(), "nonce", 2_000, "id_token_invalid"),
            (
                {
                    let mut value = auth();
                    value.tenant_id = "other".to_owned();
                    value
                },
                "nonce",
                1_000,
                "tenant_mismatch",
            ),
        ] {
            assert_eq!(
                validate_id_token(&token, &jwks, &configured, nonce, now)
                    .expect_err("rejected")
                    .code,
                expected
            );
        }
        let (token, jwks) = signed_token(
            vec![
                Audience::new("client".to_owned()),
                Audience::new("api".to_owned()),
            ],
            None,
            "tenant",
        );
        assert_eq!(
            validate_id_token(&token, &jwks, &auth(), "nonce", 1_000)
                .expect_err("missing azp")
                .code,
            "authorized_party_mismatch"
        );
    }

    #[test]
    fn id_token_shape_requires_subject_and_issue_time() {
        let missing = json!({
            "iss":"https://issuer.example/", "aud":"client", "exp":2_000,
            "nonce":"nonce", "tenantId":"tenant"
        });
        assert!(
            serde_json::from_value::<IdTokenClaims<TenantClaims, CoreGenderClaim>>(missing)
                .is_err()
        );
    }

    #[test]
    fn rendered_diagnostics_include_a_closed_stage() {
        let rendered = AppError::transport("request_failed", true).render();
        assert_eq!(rendered["diagnostic"]["stage"], "transport");
    }

    #[test]
    fn jwks_policy_and_typed_verifier_reject_non_signing_wrong_alg_and_duplicate_keys() {
        assert!(validate_jwks_key_operations(br#"{"keys":[{"key_ops":["verify"]}]}"#).is_ok());
        for body in [
            br#"{"keys":[{"key_ops":["encrypt"]}]}"#.as_slice(),
            br#"{"keys":[{"key_ops":["verify","sign"]}]}"#.as_slice(),
        ] {
            assert_eq!(
                validate_jwks_key_operations(body)
                    .expect_err("key operations")
                    .code,
                "id_token_key_usage"
            );
        }

        let (token, jwks) = signed_token(vec![Audience::new("client".to_owned())], None, "tenant");
        for mutation in ["use", "alg", "duplicate"] {
            let mut value = serde_json::to_value(&jwks).expect("jwks");
            let keys = value["keys"].as_array_mut().expect("keys");
            match mutation {
                "use" => keys[0]["use"] = json!("enc"),
                "alg" => keys[0]["alg"] = json!("RS512"),
                "duplicate" => keys.push(keys[0].clone()),
                _ => unreachable!(),
            }
            let invalid: CoreJsonWebKeySet = serde_json::from_value(value).expect("typed jwks");
            assert_eq!(
                validate_id_token(&token, &invalid, &auth(), "nonce", 1_000)
                    .expect_err("invalid key policy")
                    .code,
                "id_token_invalid",
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn rss_base_url_is_an_https_origin() {
        assert!(validate_rss_base_url(&Url::parse("https://rss.example/").expect("url")).is_ok());
        for value in [
            "http://rss.example/",
            "https://rss.example/proxy",
            "https://rss.example/proxy/",
            "https://rss.example/?query=1",
            "https://user@rss.example/",
        ] {
            assert!(
                validate_rss_base_url(&Url::parse(value).expect("url")).is_err(),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn callback_ignores_invalid_connections_reads_fragments_and_completes_browser_pages() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("address");
        let redirect = Url::parse(&format!("http://{address}/callback")).expect("redirect");
        let task =
            tokio::spawn(async move { receive_callback(listener, &redirect, "expected").await });

        let mut invalid = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        invalid
            .write_all(
                b"GET /wrong?state=expected&code=ignored HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            .await
            .expect("invalid request");
        let mut invalid_response = Vec::new();
        invalid
            .read_to_end(&mut invalid_response)
            .await
            .expect("response");
        assert!(String::from_utf8_lossy(&invalid_response).contains("400 Bad Request"));

        let mut valid = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        valid
            .write_all(b"GET /callback?state=expected&code=split")
            .await
            .expect("fragment one");
        tokio::task::yield_now().await;
        valid
            .write_all(b" HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("fragment two");
        let mut valid_response = Vec::new();
        valid
            .read_to_end(&mut valid_response)
            .await
            .expect("response");
        assert!(String::from_utf8_lossy(&valid_response).contains("200 OK"));
        assert_eq!(task.await.expect("task").expect("callback"), "split");
    }

    #[tokio::test]
    async fn callback_reports_authorization_rejection_to_browser_before_returning() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("address");
        let redirect = Url::parse(&format!("http://{address}/callback")).expect("redirect");
        let task =
            tokio::spawn(async move { receive_callback(listener, &redirect, "expected").await });
        let mut socket = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        socket
            .write_all(b"GET /callback?state=expected&error=access_denied HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("request");
        let mut response = Vec::new();
        socket.read_to_end(&mut response).await.expect("response");
        assert!(String::from_utf8_lossy(&response).contains("Authentication rejected."));
        assert_eq!(
            task.await.expect("task").expect_err("rejected").code,
            "authorization_rejected"
        );
    }

    #[tokio::test]
    async fn callback_connection_budget_does_not_refresh_after_each_fragment() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("address");
        let read = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            read_callback_headers(&mut socket).await
        });
        let mut socket = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        socket.write_all(b"G").await.expect("first fragment");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        socket.write_all(b"E").await.expect("second fragment");
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        let _ = socket
            .write_all(b"T /callback HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        assert_eq!(
            read.await
                .expect("read task")
                .expect_err("one connection budget")
                .code,
            "callback_connection_timeout"
        );
    }

    #[test]
    fn remote_plaintext_is_forbidden_but_loopback_callback_is_allowed() {
        assert!(
            secure_remote_url(&Url::parse("https://api.example/").expect("url"), false).is_ok()
        );
        assert!(secure_remote_url(&Url::parse("http://api.example/").expect("url"), true).is_err());
        assert!(
            secure_remote_url(&Url::parse("http://127.0.0.1:8000/").expect("url"), true).is_ok()
        );
    }

    #[test]
    fn discovery_preserves_keycloak_realm_path_and_issuer_identity_is_exact() {
        let issuer = Url::parse("https://issuer.example/realms/device").expect("issuer");
        assert_eq!(
            discovery_url(&issuer).expect("discovery").as_str(),
            "https://issuer.example/realms/device/.well-known/openid-configuration"
        );
        let mut configured = auth();
        configured.issuer = issuer;
        let (token, jwks) = signed_token(vec![Audience::new("client".to_owned())], None, "tenant");
        assert_eq!(
            validate_id_token(&token, &jwks, &configured, "nonce", 1_000)
                .expect_err("exact issuer")
                .code,
            "id_token_invalid"
        );
    }

    #[test]
    fn multiple_audiences_require_matching_authorized_party() {
        let (token, jwks) = signed_token(
            vec![
                Audience::new("client".to_owned()),
                Audience::new("api".to_owned()),
            ],
            Some(ClientId::new("client".to_owned())),
            "tenant",
        );
        assert!(validate_id_token(&token, &jwks, &auth(), "nonce", 1_000).is_ok());
        let (token, jwks) = signed_token(
            vec![
                Audience::new("client".to_owned()),
                Audience::new("api".to_owned()),
            ],
            Some(ClientId::new("other".to_owned())),
            "tenant",
        );
        assert_eq!(
            validate_id_token(&token, &jwks, &auth(), "nonce", 1_000)
                .expect_err("wrong azp")
                .code,
            "authorized_party_mismatch"
        );
    }

    #[tokio::test]
    async fn injected_ports_drive_complete_rotate_and_typed_exit_mapping() {
        let (_directory, input) = policy_file();
        let success = FakeHttp::new(auth_replies(
            200,
            &json!({"data":{"acceptedGeneration":5,"authorizationReceiptId":"0198d5f2-70de-7a2d-b3f4-012345678905","condition":"Reconciling"}}),
        ));
        let output = rotate_with_ports(
            rotate_args(input.clone()),
            &success,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
        )
        .await
        .expect("rotate");
        assert_eq!(output["acceptedGeneration"], 5);
        assert_eq!(success.requests.lock().expect("requests").len(), 1);

        for (status, body, exit) in [
            (
                400,
                json!({"error":{"code":"ERR_CORE_VALIDATION","details":[],"message":"validation failed","requestId":"r400","retryable":false}}),
                4,
            ),
            (401, json!({"provider":"bait"}), 3),
            (403, json!({"provider":"bait"}), 3),
            (
                404,
                json!({"error":{"code":"ERR_CORE_NOT_FOUND","details":[],"message":"not found","requestId":"r404","retryable":false}}),
                4,
            ),
            (
                409,
                json!({"error":{"code":"ERR_CORE_VERSION_CONFLICT","details":[],"message":"version conflict","requestId":"r409","retryable":true}}),
                4,
            ),
            (429, json!({"provider":"bait"}), 5),
            (503, json!({"provider":"bait"}), 5),
            (200, json!({"malformed":true}), 6),
        ] {
            let fake = FakeHttp::new(auth_replies(status, &body));
            let error = rotate_with_ports(
                rotate_args(input.clone()),
                &fake,
                &FakeBrowser,
                &FakeClock,
                &FakeCallback,
                &FakeVerifier,
            )
            .await
            .expect_err("classified");
            assert_eq!(error.exit_code(), exit);
            assert!(!error.render().to_string().contains("provider"));
        }
    }

    #[tokio::test]
    async fn oidc_transport_and_malformed_responses_keep_exit_classes() {
        let transport = FakeHttp::new(vec![Err(AppError::transport("request_timeout", true))]);
        let error = authenticate(
            &auth(),
            &transport,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
        )
        .await
        .expect_err("transport");
        assert_eq!(error.exit_code(), 5);
        assert_eq!(error.render()["diagnostic"]["stage"], "discovery");
        let malformed = FakeHttp::new(vec![Ok(HttpReply {
            status: 200,
            body: b"not-json".to_vec(),
        })]);
        let error = authenticate(
            &auth(),
            &malformed,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
        )
        .await
        .expect_err("malformed");
        assert_eq!(error.exit_code(), 6);
        assert_eq!(error.render()["diagnostic"]["stage"], "discovery");
    }

    #[tokio::test]
    async fn login_timeout_is_one_end_to_end_budget() {
        let http = DelayedHttp {
            inner: FakeHttp::new(vec![
                Ok(reply(
                    200,
                    &json!({"issuer":"https://issuer.example/","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
                )),
                Ok(reply(
                    200,
                    &json!({"access_token":"token-bait","id_token":"id-token-bait"}),
                )),
            ]),
            delay: Duration::from_millis(30),
        };
        let error = authenticate_with_limit(
            &auth(),
            &http,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
            Duration::from_millis(50),
        )
        .await
        .expect_err("single budget");
        assert_eq!(error.code, "login_timeout");
    }

    #[tokio::test]
    async fn login_timeout_reports_the_active_stage() {
        let http = DelayedHttp {
            inner: FakeHttp::new(vec![Ok(reply(
                200,
                &json!({"issuer":"https://issuer.example/","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
            ))]),
            delay: Duration::from_millis(50),
        };
        let error = authenticate_with_limit(
            &auth(),
            &http,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
            Duration::from_millis(20),
        )
        .await
        .expect_err("discovery timeout");
        assert_eq!(error.code, "login_timeout");
        assert_eq!(error.stage.as_str(), "discovery");
    }

    #[tokio::test]
    async fn oidc_token_statuses_and_invalid_discovery_endpoints_keep_exit_classes() {
        for (status, exit) in [(400, 3), (401, 3), (403, 3), (429, 5), (503, 5), (418, 6)] {
            let fake = FakeHttp::new(vec![
                Ok(reply(
                    200,
                    &json!({"issuer":"https://issuer.example/","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
                )),
                Ok(reply(status, &json!({"provider":"secret-bait"}))),
            ]);
            let error = authenticate(
                &auth(),
                &fake,
                &FakeBrowser,
                &FakeClock,
                &FakeCallback,
                &FakeVerifier,
            )
            .await
            .expect_err("token status");
            assert_eq!(error.exit_code(), exit, "status {status}");
            assert_eq!(error.render()["diagnostic"]["stage"], "token_exchange");
            assert!(!error.render().to_string().contains("secret-bait"));
        }

        let invalid_discovery = FakeHttp::new(vec![Ok(reply(
            200,
            &json!({"issuer":"https://issuer.example/","authorization_endpoint":"not a URL","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
        ))]);
        assert_eq!(
            authenticate(
                &auth(),
                &invalid_discovery,
                &FakeBrowser,
                &FakeClock,
                &FakeCallback,
                &FakeVerifier,
            )
            .await
            .expect_err("invalid discovery endpoint")
            .exit_code(),
            6
        );
    }

    #[tokio::test]
    async fn http_deadline_includes_response_body_consumption() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).await.expect("request");
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n")
                .await
                .expect("headers");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let result = ReqwestHttpPort::new(None)
            .expect("http")
            .get(
                Url::parse(&format!("http://{address}/slow")).expect("url"),
                Duration::from_millis(50),
            )
            .await;
        let Err(result) = result else {
            panic!("body should time out");
        };
        assert_eq!(result.code, "request_timeout");
        assert_eq!(result.exit_code(), 5);
        server.abort();
    }

    #[tokio::test]
    async fn injected_ports_drive_complete_status_without_ready_inference() {
        let fake = FakeHttp::new(auth_replies(
            200,
            &json!({"data":{"conditions":[{"lastTransitionAt":10,"observedGeneration":4,"reason":"AwaitingDevice","status":"Unknown","type":"PendingDevice"}],"desired":{"activeCommand":{"fenceEpoch":2,"state":"queued"},"authorizationReceiptId":"0198d5f2-70de-7a2d-b3f4-012345678905","generation":5},"observedGeneration":4}}),
        ));
        let output = status_with_ports(
            status_args(),
            &fake,
            &FakeBrowser,
            &FakeClock,
            &FakeCallback,
            &FakeVerifier,
        )
        .await
        .expect("status");
        assert_eq!(output["desiredGeneration"], 5);
        assert_eq!(output["observedGeneration"], 4);
        assert_eq!(output["conditions"][0]["type"], "PendingDevice");
        assert!(output.get("ready").is_none());
    }

    #[tokio::test]
    async fn api_port_sends_exact_headers_method_path_and_canonical_body() {
        let server = MockServer::start().await;
        let device = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678901").expect("device");
        let idempotency = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678902").expect("key");
        let request_id = Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678903").expect("request");
        let correlation_id =
            Uuid::parse_str("0198d5f2-70de-7a2d-b3f4-012345678904").expect("correlation");
        let policy = RotationPolicy::try_new(vec![KeyUsage::ClientAuth], 600, Vec::new(), 3_600)
            .expect("policy");
        let prepared = prepare_policy_put(device, 4, idempotency, &policy).expect("prepared");
        Mock::given(method("PUT"))
            .and(path(format!("/api/v2/identity/devices/{device}/certificate-policy")))
            .and(header("authorization", "Bearer token-bait"))
            .and(header("x-tenant-id", "tenant-one"))
            .and(header("x-request-id", request_id.to_string()))
            .and(header("x-correlation-id", correlation_id.to_string()))
            .and(body_json(json!({"expectedGeneration":4,"idempotencyKey":idempotency,"policy":{"keyUsages":["clientAuth"],"renewBeforeSeconds":600,"validitySeconds":3600}})))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":{"acceptedGeneration":5,"authorizationReceiptId":"0198d5f2-70de-7a2d-b3f4-012345678905","condition":"Reconciling"}})))
            .expect(1).mount(&server).await;
        let response = send_api(
            &Url::parse(&server.uri()).expect("base"),
            &prepared,
            &TokenSet {
                access_token: "token-bait".to_owned(),
            },
            "tenant-one",
            request_id,
            correlation_id,
            &ReqwestHttpPort::new(None).expect("http"),
        )
        .await
        .expect("response");
        assert_eq!(response.0, 200);
    }

    #[tokio::test]
    async fn api_port_rejects_oversize_body_without_exposing_it() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'x'; MAX_RESPONSE_BYTES + 1]),
            )
            .mount(&server)
            .await;
        let result = send_api(
            &Url::parse(&server.uri()).expect("base"),
            &prepare_status_get(Uuid::nil()),
            &TokenSet {
                access_token: "secret".to_owned(),
            },
            "tenant",
            Uuid::new_v4(),
            Uuid::new_v4(),
            &ReqwestHttpPort::new(None).expect("http"),
        )
        .await
        .expect_err("oversize");
        assert_eq!(result.code, "response_oversize");
        assert!(!format!("{result:?}").contains("secret"));
    }
}
