#![doc = "First-party Plain Rust consumer of RSS standalone observation components."]

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::Request;
use rss_diag_context::{CorrelationId, DiagnosticCtx, scope};
use rss_trace_context::{TraceParent, restore_remote_parent};
use tower::{Layer, Service};
use tracing::Instrument as _;

/// Binds diagnostic and W3C trace context around one Tower request future.
#[derive(Clone, Copy, Debug, Default)]
pub struct ObservationLayer;

impl<S> Layer<S> for ObservationLayer {
    type Service = ObservationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ObservationService { inner }
    }
}

/// Tower service produced by [`ObservationLayer`].
#[derive(Clone, Debug)]
pub struct ObservationService<S> {
    inner: S,
}

impl<S, B> Service<Request<B>> for ObservationService<S>
where
    S: Service<Request<B>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let diagnostic = diagnostic_context(&request);
        let traceparent = traceparent(&request);
        let tracestate = request
            .headers()
            .get("tracestate")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let span = tracing::info_span!(parent: None, "plain_rust_request");
        if let Some(parent) = traceparent.as_ref() {
            let _ = restore_remote_parent(&span, parent, tracestate.as_deref());
        }
        let future = self.inner.call(request).instrument(span);
        Box::pin(async move {
            match diagnostic {
                Some(context) => scope(context, future).await,
                None => future.await,
            }
        })
    }
}

fn diagnostic_context<B>(request: &Request<B>) -> Option<DiagnosticCtx> {
    request
        .headers()
        .get("x-correlation-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| CorrelationId::parse(value).ok())
        .map(DiagnosticCtx::new)
}

fn traceparent<B>(request: &Request<B>) -> Option<TraceParent> {
    request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| TraceParent::parse(value).ok())
}
