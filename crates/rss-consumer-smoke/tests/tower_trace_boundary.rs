use http::{HeaderValue, Request, StatusCode};
use opentelemetry::trace::TracerProvider as _;
use rss_consumer_smoke::ObservationLayer;
use rss_diag_context::correlation;
use rss_trace_context::capture_current;
use tower::{ServiceBuilder, ServiceExt, service_fn};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::prelude::*;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[tokio::test]
async fn valid_headers_bind_scope_and_restore_remote_parent() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));

    let (status, correlation, captured) = async {
        service()
            .oneshot(request("request-42", TRACEPARENT))
            .await
            .expect("infallible service")
    }
    .with_subscriber(subscriber)
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(correlation.as_deref(), Some("request-42"));
    assert_eq!(captured_trace_id(captured.as_ref()), Some(TRACE_ID));
    provider.shutdown().expect("provider shutdown");
}

#[tokio::test]
async fn malformed_observation_headers_do_not_inherit_input_trace() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));
    let oversized_correlation = "a".repeat(129);
    let oversized_traceparent = format!("{TRACEPARENT}{}", "a".repeat(458));
    let malformed_traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-GG";
    let unsupported_traceparent = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    async {
        for (correlation, traceparent) in [
            ("bad value", malformed_traceparent),
            (
                oversized_correlation.as_str(),
                oversized_traceparent.as_str(),
            ),
            ("", unsupported_traceparent),
        ] {
            let (status, correlation, captured) = service()
                .oneshot(request(correlation, traceparent))
                .await
                .expect("infallible service");
            assert_eq!(status, StatusCode::OK);
            assert!(correlation.is_none());
            assert_ne!(captured_trace_id(captured.as_ref()), Some(TRACE_ID));
        }
    }
    .with_subscriber(subscriber)
    .await;
    provider.shutdown().expect("provider shutdown");
}

#[tokio::test]
async fn missing_otel_layer_keeps_valid_observation_fail_open() {
    let (status, correlation, captured) = service()
        .oneshot(request("request-42", TRACEPARENT))
        .await
        .expect("infallible service");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(correlation.as_deref(), Some("request-42"));
    assert!(captured.is_none());
}

#[tokio::test]
async fn duplicate_observation_headers_are_ambiguous_and_ignored() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));
    async {
        for reverse in [false, true] {
            let mut request = request("request-42", TRACEPARENT);
            let headers = request.headers_mut();
            if reverse {
                headers.insert("x-correlation-id", HeaderValue::from_static("bad value"));
                headers.append("x-correlation-id", HeaderValue::from_static("request-42"));
                headers.insert("traceparent", HeaderValue::from_static("not-a-traceparent"));
                headers.append("traceparent", HeaderValue::from_static(TRACEPARENT));
            } else {
                headers.append("x-correlation-id", HeaderValue::from_static("bad value"));
                headers.append("traceparent", HeaderValue::from_static("not-a-traceparent"));
            }
            let (status, correlation, captured) = service()
                .oneshot(request)
                .await
                .expect("infallible service");
            assert_eq!(status, StatusCode::OK);
            assert!(correlation.is_none());
            assert_ne!(captured_trace_id(captured.as_ref()), Some(TRACE_ID));
        }
    }
    .with_subscriber(subscriber)
    .await;
    provider.shutdown().expect("provider shutdown");
}

#[tokio::test]
async fn invalid_or_oversized_tracestate_is_dropped_without_losing_parent() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));
    let oversized = "a".repeat(513);
    async {
        for tracestate in ["INVALID KEY=value", oversized.as_str()] {
            let mut request = request("request-42", TRACEPARENT);
            request.headers_mut().insert(
                "tracestate",
                HeaderValue::from_str(tracestate).expect("ASCII tracestate"),
            );
            let (_, _, captured) = service()
                .oneshot(request)
                .await
                .expect("infallible service");
            let (traceparent, tracestate) = captured.expect("valid parent remains available");
            assert_eq!(trace_id(Some(&traceparent)), Some(TRACE_ID));
            assert!(tracestate.is_none());
        }

        let mut valid = request("request-42", TRACEPARENT);
        valid
            .headers_mut()
            .insert("tracestate", HeaderValue::from_static("vendor=value"));
        let (_, _, captured) = service().oneshot(valid).await.expect("infallible service");
        let (_, tracestate) = captured.expect("valid context remains available");
        assert_eq!(tracestate.as_deref(), Some("vendor=value"));
    }
    .with_subscriber(subscriber)
    .await;
    provider.shutdown().expect("provider shutdown");
}

type ServiceResponse = (StatusCode, Option<String>, Option<(String, Option<String>)>);

fn service()
-> impl tower::Service<Request<()>, Response = ServiceResponse, Error = std::convert::Infallible> + Clone
{
    ServiceBuilder::new()
        .layer(ObservationLayer)
        .service(service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>((
                StatusCode::OK,
                correlation().map(|id| id.as_str().to_owned()),
                capture_current().map(|context| {
                    (
                        context.traceparent().as_str().to_owned(),
                        context.tracestate().map(str::to_owned),
                    )
                }),
            ))
        }))
}

fn request(correlation: &str, traceparent: &str) -> Request<()> {
    Request::builder()
        .header("x-correlation-id", correlation)
        .header("traceparent", traceparent)
        .body(())
        .expect("ASCII observation headers")
}

fn captured_trace_id(captured: Option<&(String, Option<String>)>) -> Option<&str> {
    trace_id(captured.map(|(traceparent, _)| traceparent.as_str()))
}

fn trace_id(traceparent: Option<&str>) -> Option<&str> {
    traceparent?.split('-').nth(1)
}
