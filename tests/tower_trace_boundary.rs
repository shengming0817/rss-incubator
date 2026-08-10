use http::{Request, StatusCode};
use opentelemetry::trace::TracerProvider as _;
use rss_diag_context::correlation;
use rss_standalone_consumer::ObservationLayer;
use rss_trace_context::capture_current;
use tower::{ServiceBuilder, ServiceExt, service_fn};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::prelude::*;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

#[tokio::test]
async fn valid_headers_bind_scope_and_restore_remote_parent() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));

    let (status, correlation, traceparent) = async {
        service()
            .oneshot(
                Request::builder()
                    .header("x-correlation-id", "request-42")
                    .header("traceparent", TRACEPARENT)
                    .body(())
                    .expect("fixed request"),
            )
            .await
            .expect("infallible service")
    }
    .with_subscriber(subscriber)
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(correlation.as_deref(), Some("request-42"));
    assert_eq!(
        trace_id(
            traceparent
                .as_ref()
                .map(rss_trace_context::TraceParent::as_str)
        ),
        trace_id(Some(TRACEPARENT))
    );
    provider.shutdown().expect("provider shutdown");
}

#[tokio::test]
async fn malformed_observation_headers_do_not_change_service_result() {
    let oversized = "a".repeat(129);
    for (correlation, traceparent) in [
        ("", "not-a-traceparent"),
        ("bad value", TRACEPARENT),
        (
            oversized.as_str(),
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ),
    ] {
        let response = service()
            .oneshot(
                Request::builder()
                    .header("x-correlation-id", correlation)
                    .header("traceparent", traceparent)
                    .body(())
                    .expect("fixed request"),
            )
            .await
            .expect("infallible service");
        assert_eq!(response.0, StatusCode::OK);
        assert!(response.1.is_none());
    }
}

#[tokio::test]
async fn invalid_tracestate_drops_state_without_losing_parent() {
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("consumer")));
    let (_, _, captured) = async {
        service()
            .oneshot(
                Request::builder()
                    .header("traceparent", TRACEPARENT)
                    .header("tracestate", "INVALID KEY=value")
                    .body(())
                    .expect("fixed request"),
            )
            .await
            .expect("infallible service")
    }
    .with_subscriber(subscriber)
    .await;
    let captured = captured.expect("valid parent remains available");
    assert_eq!(
        trace_id(Some(captured.as_str())),
        trace_id(Some(TRACEPARENT))
    );
    provider.shutdown().expect("provider shutdown");
}

fn service() -> impl tower::Service<
    Request<()>,
    Response = (
        StatusCode,
        Option<String>,
        Option<rss_trace_context::TraceParent>,
    ),
    Error = std::convert::Infallible,
> + Clone {
    ServiceBuilder::new()
        .layer(ObservationLayer)
        .service(service_fn(|_: Request<()>| async move {
            Ok::<_, std::convert::Infallible>((
                StatusCode::OK,
                correlation().map(|id| id.as_str().to_owned()),
                capture_current().map(rss_trace_context::W3cTraceContext::into_traceparent),
            ))
        }))
}

fn trace_id(traceparent: Option<&str>) -> Option<&str> {
    traceparent?.split('-').nth(1)
}
