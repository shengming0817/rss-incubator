#![doc = "Safe JSON-only control CLI for device certificate rotation."]

use std::{
    fs,
    io::{self, Read},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use clap::{Args, Parser, Subcommand, error::ErrorKind};
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use openidconnect::PkceCodeChallenge;
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
    time::timeout,
};
use url::Url;
use uuid::Uuid;

pub const LOGIN_TIMEOUT: Duration = Duration::from_mins(2);
pub const API_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

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
    id_token: String,
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    aud: Audience,
    exp: u64,
    nonce: String,
    #[serde(default)]
    azp: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

const CALLBACK_INVALID: &str = "callback_invalid";
const INVALID_DISCOVERY: &str = "invalid_discovery";
const INPUT_UNREADABLE: &str = "input_unreadable";
const RESPONSE_OVERSIZE: &str = "response_oversize";

#[derive(Debug)]
pub struct AppError {
    code: &'static str,
    class: ErrorClass,
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

impl AppError {
    fn input(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Input,
            request_id: None,
            retryable: false,
        }
    }
    fn auth(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Auth,
            request_id: None,
            retryable: false,
        }
    }
    fn transport(code: &'static str, retryable: bool) -> Self {
        Self {
            code,
            class: ErrorClass::Transport,
            request_id: None,
            retryable,
        }
    }
    fn untrusted(code: &'static str) -> Self {
        Self {
            code,
            class: ErrorClass::Untrusted,
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
            request_id: value.request_id().map(ToOwned::to_owned),
            retryable: value.retryable(),
        }
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
        json!({"schemaVersion":"1","outcome":"error","diagnostic":{"category":match self.class { ErrorClass::Input => "input", ErrorClass::Auth => "auth", ErrorClass::Typed => "typed", ErrorClass::Transport => "transport", ErrorClass::Untrusted => "untrusted" },"code":self.code,"retryable":self.retryable,"requestId":self.request_id}})
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
            AppError::transport("runtime_unavailable", false).render()
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
        token: &str,
        jwks: &JwkSet,
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
        webbrowser::open(url.as_str()).map_err(|_| AppError::auth("browser_launch_failed"))
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
        token: &str,
        jwks: &JwkSet,
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
        .map_err(|_| AppError::auth("callback_bind_failed"))?;
        browser.open(authorize)?;
        timeout(LOGIN_TIMEOUT, receive_callback(listener, redirect, state))
            .await
            .map_err(|_| AppError::auth("login_timeout"))?
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
        let response = timeout(limit, request.send())
            .await
            .map_err(|_| AppError::transport("request_timeout", true))?
            .map_err(|_| AppError::transport("request_failed", true))?;
        let status = response.status().as_u16();
        let body = bounded_bytes(response).await?;
        Ok(HttpReply { status, body })
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
    let discovery: Discovery =
        fetch_json(http, discovery_url(&auth.issuer)?, LOGIN_TIMEOUT).await?;
    if discovery.issuer != auth.issuer.as_str() {
        return Err(AppError::auth("issuer_mismatch"));
    }
    let authorization_endpoint = Url::parse(&discovery.authorization_endpoint)
        .map_err(|_| AppError::auth(INVALID_DISCOVERY))?;
    let token_endpoint =
        Url::parse(&discovery.token_endpoint).map_err(|_| AppError::auth(INVALID_DISCOVERY))?;
    let jwks_uri =
        Url::parse(&discovery.jwks_uri).map_err(|_| AppError::auth(INVALID_DISCOVERY))?;
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
    let code = callback
        .authorize(&auth.redirect_uri, &state, &authorize, browser)
        .await?;
    let response = http
        .post_form(
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
        )
        .await?;
    if response.status != StatusCode::OK.as_u16() {
        return Err(AppError::auth("token_exchange_rejected"));
    }
    let token: TokenWire = serde_json::from_slice(&response.body)
        .map_err(|_| AppError::untrusted("malformed_json"))?;
    let jwks: JwkSet = fetch_json(http, jwks_uri, LOGIN_TIMEOUT).await?;
    verifier.verify(&token.id_token, &jwks, auth, &nonce, clock.unix_seconds()?)?;
    Ok(TokenSet {
        access_token: token.access_token,
    })
}

async fn receive_callback(
    listener: TcpListener,
    redirect: &Url,
    expected_state: &str,
) -> Result<String, AppError> {
    let (mut socket, _) = listener
        .accept()
        .await
        .map_err(|_| AppError::auth("callback_failed"))?;
    let mut request = vec![0_u8; 8192];
    let count = socket
        .read(&mut request)
        .await
        .map_err(|_| AppError::auth("callback_failed"))?;
    let first = std::str::from_utf8(&request[..count])
        .map_err(|_| AppError::auth(CALLBACK_INVALID))?
        .lines()
        .next()
        .ok_or_else(|| AppError::auth(CALLBACK_INVALID))?;
    let target = first
        .strip_prefix("GET ")
        .and_then(|value| value.split_once(' ').map(|pair| pair.0))
        .ok_or_else(|| AppError::auth(CALLBACK_INVALID))?;
    let callback = redirect
        .join(target)
        .map_err(|_| AppError::auth(CALLBACK_INVALID))?;
    if callback.path() != redirect.path() {
        return Err(AppError::auth(CALLBACK_INVALID));
    }
    let params = callback
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    if params.get("state").map(std::convert::AsRef::as_ref) != Some(expected_state) {
        return Err(AppError::auth("state_mismatch"));
    }
    let code = params
        .get("code")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::auth("authorization_rejected"))?
        .to_string();
    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 24\r\nConnection: close\r\n\r\nAuthentication complete.").await;
    Ok(code)
}

fn validate_id_token(
    token: &str,
    jwks: &JwkSet,
    auth: &AuthArgs,
    nonce: &str,
    now: u64,
) -> Result<(), AppError> {
    let header = decode_header(token).map_err(|_| AppError::auth("id_token_invalid"))?;
    if header.alg != Algorithm::RS256 {
        return Err(AppError::auth("id_token_algorithm"));
    }
    let kid = header
        .kid
        .ok_or_else(|| AppError::auth("id_token_key_missing"))?;
    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| AppError::auth("id_token_key_unknown"))?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| AppError::auth("id_token_key_invalid"))?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(&[auth.issuer.as_str()]);
    let claims = decode::<IdClaims>(token, &key, &validation)
        .map_err(|_| AppError::auth("id_token_invalid"))?
        .claims;
    validate_claims(&claims, auth, nonce, now)
}

fn validate_claims(
    claims: &IdClaims,
    auth: &AuthArgs,
    nonce: &str,
    now: u64,
) -> Result<(), AppError> {
    if claims.iss != auth.issuer.as_str() {
        return Err(AppError::auth("issuer_mismatch"));
    }
    if claims.exp <= now {
        return Err(AppError::auth("token_expired"));
    }
    if !claims.aud.contains(&auth.client_id) {
        return Err(AppError::auth("audience_mismatch"));
    }
    if matches!(claims.aud, Audience::Many(_)) && claims.azp.as_deref() != Some(&auth.client_id) {
        return Err(AppError::auth("authorized_party_mismatch"));
    }
    if claims
        .azp
        .as_deref()
        .is_some_and(|azp| azp != auth.client_id)
    {
        return Err(AppError::auth("authorized_party_mismatch"));
    }
    if claims.nonce != nonce {
        return Err(AppError::auth("nonce_mismatch"));
    }
    if claims.tenant_id != auth.tenant_id {
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
    secure_remote_url(&args.rss_base_url, false)?;
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
    secure_remote_url(&args.rss_base_url, false)?;
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
        .join(prepared.path().trim_start_matches('/'))
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
        .await?;
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
) -> Result<T, AppError> {
    let response = http.get(url, limit).await?;
    if response.status != StatusCode::OK.as_u16() {
        return Err(AppError::transport("upstream_rejected", false));
    }
    serde_json::from_slice(&response.body).map_err(|_| AppError::untrusted("malformed_json"))
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
    use std::{collections::VecDeque, sync::Mutex};
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

    fn claims() -> IdClaims {
        IdClaims {
            iss: "https://issuer.example/".to_owned(),
            aud: Audience::One("client".to_owned()),
            exp: 2_000,
            nonce: "nonce".to_owned(),
            azp: None,
            tenant_id: "tenant".to_owned(),
        }
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
            token: &str,
            _: &JwkSet,
            _: &AuthArgs,
            _: &str,
            now: u64,
        ) -> Result<(), AppError> {
            assert_eq!(token, "id-token-bait");
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
    fn reply(status: u16, body: &Value) -> HttpReply {
        HttpReply {
            status,
            body: serde_json::to_vec(body).expect("body"),
        }
    }
    fn auth_replies(api_status: u16, api_body: &Value) -> Vec<Result<HttpReply, AppError>> {
        vec![
            Ok(reply(
                200,
                &json!({"issuer":"https://issuer.example/","authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks"}),
            )),
            Ok(reply(
                200,
                &json!({"access_token":"token-bait","id_token":"id-token-bait"}),
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
    fn claims_reject_issuer_audience_nonce_expiry_and_tenant_mismatch() {
        assert!(validate_claims(&claims(), &auth(), "nonce", 1_000).is_ok());
        let mut value = claims();
        value.iss = "https://other.example/".to_owned();
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("issuer")
                .code,
            "issuer_mismatch"
        );
        let mut value = claims();
        value.aud = Audience::One("other".to_owned());
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("aud")
                .code,
            "audience_mismatch"
        );
        assert_eq!(
            validate_claims(&claims(), &auth(), "wrong", 1_000)
                .expect_err("nonce")
                .code,
            "nonce_mismatch"
        );
        assert_eq!(
            validate_claims(&claims(), &auth(), "nonce", 2_000)
                .expect_err("expiry")
                .code,
            "token_expired"
        );
        let mut value = claims();
        value.tenant_id = "other".to_owned();
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("tenant")
                .code,
            "tenant_mismatch"
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
        let mut value = claims();
        value.iss = "https://issuer.example/realms/device/".to_owned();
        assert_eq!(
            validate_claims(&value, &configured, "nonce", 1_000)
                .expect_err("exact issuer")
                .code,
            "issuer_mismatch"
        );
    }

    #[test]
    fn multiple_audiences_require_matching_authorized_party() {
        let mut value = claims();
        value.aud = Audience::Many(vec!["client".to_owned(), "api".to_owned()]);
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
                .expect_err("missing azp")
                .code,
            "authorized_party_mismatch"
        );
        value.azp = Some("client".to_owned());
        assert!(validate_claims(&value, &auth(), "nonce", 1_000).is_ok());
        value.azp = Some("other".to_owned());
        assert_eq!(
            validate_claims(&value, &auth(), "nonce", 1_000)
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
        assert_eq!(
            authenticate(
                &auth(),
                &transport,
                &FakeBrowser,
                &FakeClock,
                &FakeCallback,
                &FakeVerifier
            )
            .await
            .expect_err("transport")
            .exit_code(),
            5
        );
        let malformed = FakeHttp::new(vec![Ok(HttpReply {
            status: 200,
            body: b"not-json".to_vec(),
        })]);
        assert_eq!(
            authenticate(
                &auth(),
                &malformed,
                &FakeBrowser,
                &FakeClock,
                &FakeCallback,
                &FakeVerifier
            )
            .await
            .expect_err("malformed")
            .exit_code(),
            6
        );
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
