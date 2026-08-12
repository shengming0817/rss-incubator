#![doc = "External Platform vNext contract-authoring and asynchronous-handler consumer."]

use rss_contract::ContractDescriptor;
use rss_platform::{Contract, Handler, HandlerError, HandlerFuture};
use rss_request_context::{PrincipalKind, RequestContextView, RowScope};

/// A product-owned request authored without RSS generated or internal crates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateWidgetRequest {
    Create { name: String },
    Fail,
    Wait,
}

/// Observable values read by the asynchronous product handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateWidgetResponse {
    pub name: String,
    pub tenant: Option<String>,
    pub request_id: String,
    pub principal_kind: PrincipalKind,
    pub row_scope: Option<RowScope>,
    pub name_visible: bool,
    pub deadline_active: bool,
    pub cancellation_observed: bool,
}

/// Product-owned typed contract marker.
pub struct CreateWidget;

impl Contract for CreateWidget {
    type Request = CreateWidgetRequest;
    type Response = CreateWidgetResponse;

    const DESCRIPTOR: ContractDescriptor = ContractDescriptor::from_static(
        "widget.create",
        1,
        "sha256:1c4b4d83a61c8bd2ca64ef5dba2bd38a8f2532056987877ea332d17c0b0d8c7b",
    );
}

/// Product-owned asynchronous implementation of [`CreateWidget`].
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateWidgetHandler;

impl Handler<CreateWidget> for CreateWidgetHandler {
    fn handle<'a>(
        &'a self,
        request: CreateWidgetRequest,
        context: RequestContextView<'a>,
    ) -> HandlerFuture<'a, CreateWidgetResponse> {
        Box::pin(async move {
            let name = match request {
                CreateWidgetRequest::Create { name } => name,
                CreateWidgetRequest::Fail => return Err(HandlerError),
                CreateWidgetRequest::Wait => std::future::pending().await,
            };
            Ok(CreateWidgetResponse {
                name_visible: context.obligations().field_mask().allows("name"),
                name,
                tenant: context.tenant().map(ToString::to_string),
                request_id: context.request_id().as_str().to_owned(),
                principal_kind: context.principal().kind(),
                row_scope: context.obligations().row_scope(),
                deadline_active: context
                    .deadline()
                    .remaining(std::time::Instant::now())
                    .is_some(),
                cancellation_observed: context.cancellation().is_cancelled(),
            })
        })
    }
}
