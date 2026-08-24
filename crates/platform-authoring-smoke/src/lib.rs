#![doc = "External Platform vNext contract-authoring and asynchronous-handler consumer."]

use rss_contract::{
    ContractDescriptor, DataClass, PageCursor, PageCursorError, SafeError, SafeErrorCode,
    Timepoint, TimepointError,
};
use rss_platform::{Contract, Handler, HandlerError, HandlerFailureClass, HandlerFuture};
use rss_request_context::{PrincipalKind, RequestContextView, RowScope};

/// Product-owned record assembled exclusively from public Foundation values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FoundationRecord {
    recorded_at: Timepoint,
    next_cursor: PageCursor,
    data_class: DataClass,
}

impl FoundationRecord {
    /// Returns the authority-free absolute timestamp supplied by the caller.
    #[must_use]
    pub const fn recorded_at(&self) -> Timepoint {
        self.recorded_at
    }

    /// Returns the opaque cursor without interpreting its provider-owned contents.
    #[must_use]
    pub const fn next_cursor(&self) -> &PageCursor {
        &self.next_cursor
    }

    /// Returns the closed public data classification.
    #[must_use]
    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }
}

/// Closed product-boundary rejection for Foundation inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FoundationInputError {
    /// The absolute timestamp is outside the public wire range.
    Timepoint(TimepointError),
    /// The opaque cursor is malformed, oversized, or stale for this product scope.
    Cursor(PageCursorError),
    /// The data classification is not safe for this public projection.
    UnsafeData(SafeError),
}

/// Accepts public Foundation values without acquiring clock, cursor, or redaction authority.
///
/// # Errors
///
/// Returns a closed rejection when the timestamp or cursor is invalid, the cursor is stale for the
/// product scope, or the data classification is not public.
pub fn accept_foundation_record(
    unix_seconds: i64,
    raw_cursor: &str,
    data_class: DataClass,
    cursor_is_current: bool,
) -> Result<FoundationRecord, FoundationInputError> {
    let recorded_at = Timepoint::try_from(unix_seconds).map_err(FoundationInputError::Timepoint)?;
    let next_cursor = PageCursor::parse(raw_cursor).map_err(FoundationInputError::Cursor)?;
    if !cursor_is_current {
        return Err(FoundationInputError::Cursor(PageCursorError::Stale));
    }
    if data_class != DataClass::Public {
        return Err(FoundationInputError::UnsafeData(SafeError::new(
            SafeErrorCode::Forbidden,
        )));
    }
    Ok(FoundationRecord {
        recorded_at,
        next_cursor,
        data_class,
    })
}

/// Projects an opaque provider failure to the closed public error vocabulary.
///
/// The provider value is deliberately ignored and cannot become a source or message.
///
/// ```compile_fail
/// use rss_contract::SafeError;
/// let _ = SafeError::new("provider password=hunter2");
/// ```
#[must_use]
pub fn project_provider_failure(_error: &(dyn std::error::Error + 'static)) -> SafeError {
    SafeError::new(SafeErrorCode::Internal)
}

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
                CreateWidgetRequest::Fail => {
                    return Err(HandlerError::new(HandlerFailureClass::Rejected));
                }
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
