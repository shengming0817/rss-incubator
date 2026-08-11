use http::Request;
use rss_consumer_smoke::ObservationLayer;
use rss_diag_context::{DiagnosticCtx, correlation, current, scope};
use tokio::task::yield_now;
use tower::{ServiceBuilder, ServiceExt, service_fn};

#[tokio::test]
async fn concurrent_requests_keep_diagnostic_scopes_isolated() {
    let service = ServiceBuilder::new()
        .layer(ObservationLayer)
        .service(service_fn(|_: Request<()>| async move {
            yield_now().await;
            Ok::<_, std::convert::Infallible>(correlation().map(|id| id.as_str().to_owned()))
        }));

    let first = request("first");
    let second = request("second");
    let (first, second) = tokio::join!(
        service.clone().oneshot(first),
        service.clone().oneshot(second)
    );
    assert_eq!(first.expect("first request").as_deref(), Some("first"));
    assert_eq!(second.expect("second request").as_deref(), Some("second"));
    assert!(current().is_none());
}

#[tokio::test]
async fn spawned_task_requires_explicit_snapshot_rebind() {
    let context = DiagnosticCtx::new(
        rss_diag_context::CorrelationId::parse("snapshot").expect("fixed correlation"),
    );
    scope(context, async {
        let snapshot = current().expect("scope has a context");
        assert!(
            tokio::spawn(async { correlation() })
                .await
                .expect("join")
                .is_none()
        );
        let rebound = tokio::spawn(async move {
            scope(snapshot, async { correlation() })
                .await
                .map(|id| id.as_str().to_owned())
        })
        .await
        .expect("join");
        assert_eq!(rebound.as_deref(), Some("snapshot"));
    })
    .await;
}

fn request(correlation: &'static str) -> Request<()> {
    Request::builder()
        .header("x-correlation-id", correlation)
        .body(())
        .expect("fixed request")
}
