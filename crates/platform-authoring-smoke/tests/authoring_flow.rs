use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::time::{Duration, Instant};

use platform_authoring_smoke::{
    CreateWidget, CreateWidgetHandler, CreateWidgetRequest, CreateWidgetResponse,
};
use rss_contract::ContractDescriptor;
use rss_platform::{
    AdmissionPermit, AdmissionState, ApplicationBuilder, ApplicationModule, ApplicationName,
    ConditionStatus, Contract, DispatchError, DispatchOutcome, Dispatcher, HostView, ModuleName,
};
use rss_request_context::{
    Cancellation, CancellationFuture, CancellationObserver, CancellationReason, Deadline,
    FieldMaskView, ObligationsView, PrincipalKind, PrincipalRef, RequestContextView, RequestId,
    RowScope, TenantId,
};

struct TestHost(AtomicU8);

impl TestHost {
    fn new(state: AdmissionState) -> Self {
        Self(AtomicU8::new(state as u8))
    }

    fn set(&self, state: AdmissionState) {
        self.0.store(state as u8, Ordering::SeqCst);
    }
}

impl HostView for TestHost {
    fn admission_state(&self) -> AdmissionState {
        match self.0.load(Ordering::SeqCst) {
            0 => AdmissionState::Starting,
            1 => AdmissionState::Ready,
            2 => AdmissionState::Draining,
            _ => AdmissionState::Stopped,
        }
    }

    fn try_admit(&self) -> Result<Box<dyn AdmissionPermit>, AdmissionState> {
        match self.admission_state() {
            AdmissionState::Ready => Ok(Box::new(TestPermit)),
            state => Err(state),
        }
    }

    fn inventory_revision(&self) -> Option<String> {
        Some("incubator-revision".to_owned())
    }

    fn condition(&self, name: &str) -> Option<ConditionStatus> {
        (name == "consumer-ready").then_some(ConditionStatus::True)
    }
}

struct TestPermit;
impl AdmissionPermit for TestPermit {}

struct TestCancellation {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl TestCancellation {
    fn new(cancelled: bool) -> Self {
        Self {
            cancelled: AtomicBool::new(cancelled),
            notify: tokio::sync::Notify::new(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

impl CancellationObserver for TestCancellation {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn cancelled(&self, deadline: Deadline) -> CancellationFuture<'_> {
        Box::pin(async move {
            tokio::select! {
                () = async {
                    loop {
                        let notified = self.notify.notified();
                        if self.is_cancelled() {
                            break;
                        }
                        notified.await;
                    }
                } => CancellationReason::Cancelled,
                () = tokio::time::sleep_until(deadline.instant().into()) => {
                    CancellationReason::DeadlineExceeded
                }
            }
        })
    }
}

fn dispatcher(host: Arc<TestHost>) -> Dispatcher {
    ApplicationBuilder::new(
        ApplicationName::parse("incubator").expect("fixed application name"),
        host,
    )
    .module(
        ApplicationModule::new(ModuleName::parse("widgets").expect("fixed module name"))
            .handler::<CreateWidget, _>(CreateWidgetHandler),
    )
    .build()
    .expect("unique module and contract")
}

struct ContextFixture {
    tenant: TenantId,
    request_id: RequestId,
    principal: PrincipalRef,
    cancellation: TestCancellation,
}

impl ContextFixture {
    fn new(cancelled: bool) -> Self {
        Self {
            tenant: TenantId::parse("11111111-1111-4111-8111-111111111111").expect("fixed tenant"),
            request_id: RequestId::parse("request-2108").expect("fixed request id"),
            principal: PrincipalRef::new(PrincipalKind::Service, "incubator-author")
                .expect("fixed principal"),
            cancellation: TestCancellation::new(cancelled),
        }
    }

    fn view(&self, deadline: Instant) -> RequestContextView<'_> {
        RequestContextView::new(
            Some(&self.tenant),
            &self.request_id,
            &self.principal,
            Deadline::at(deadline),
            Cancellation::observe(&self.cancellation),
            ObligationsView::new(Some(RowScope::Tenant), FieldMaskView::new(&["name"])),
        )
    }
}

#[tokio::test]
async fn authored_contract_dispatches_and_reads_the_context_view() {
    let dispatcher = dispatcher(Arc::new(TestHost::new(AdmissionState::Ready)));
    let fixture = ContextFixture::new(false);
    let outcome = dispatcher
        .dispatch::<CreateWidget>(
            &CreateWidget::DESCRIPTOR,
            CreateWidgetRequest::Create {
                name: "external-widget".to_owned(),
            },
            fixture.view(Instant::now() + Duration::from_secs(1)),
        )
        .await
        .expect("ready host dispatches");

    let DispatchOutcome::Completed(response) = outcome else {
        panic!("expected completed outcome");
    };
    assert_eq!(
        response,
        CreateWidgetResponse {
            name: "external-widget".to_owned(),
            tenant: Some("11111111-1111-4111-8111-111111111111".to_owned()),
            request_id: "request-2108".to_owned(),
            principal_kind: PrincipalKind::Service,
            row_scope: Some(RowScope::Tenant),
            name_visible: true,
            deadline_active: true,
            cancellation_observed: false,
        }
    );
}

#[tokio::test]
async fn handler_failure_and_descriptor_upgrade_mismatch_fail_closed() {
    let dispatcher = dispatcher(Arc::new(TestHost::new(AdmissionState::Ready)));
    let fixture = ContextFixture::new(false);
    assert_eq!(
        dispatcher
            .dispatch::<CreateWidget>(
                &CreateWidget::DESCRIPTOR,
                CreateWidgetRequest::Fail,
                fixture.view(Instant::now() + Duration::from_secs(1)),
            )
            .await
            .expect("handler failures are closed outcomes"),
        DispatchOutcome::HandlerFailed
    );

    let incompatible = ContractDescriptor::from_static(
        "widget.create",
        2,
        "sha256:1c4b4d83a61c8bd2ca64ef5dba2bd38a8f2532056987877ea332d17c0b0d8c7b",
    );
    assert_eq!(
        dispatcher
            .dispatch::<CreateWidget>(
                &incompatible,
                CreateWidgetRequest::Create {
                    name: "rejected".to_owned(),
                },
                fixture.view(Instant::now() + Duration::from_secs(1)),
            )
            .await,
        Err(DispatchError::DescriptorMismatch)
    );
}

#[tokio::test]
async fn cancellation_and_deadline_stop_admitted_work() {
    let dispatcher = dispatcher(Arc::new(TestHost::new(AdmissionState::Ready)));
    let pre_cancelled = ContextFixture::new(true);
    assert_eq!(
        dispatcher
            .dispatch::<CreateWidget>(
                &CreateWidget::DESCRIPTOR,
                CreateWidgetRequest::Wait,
                pre_cancelled.view(Instant::now() + Duration::from_secs(1)),
            )
            .await
            .expect("pre-cancel is a closed outcome"),
        DispatchOutcome::Cancelled
    );

    let expired = ContextFixture::new(false);
    assert_eq!(
        dispatcher
            .dispatch::<CreateWidget>(
                &CreateWidget::DESCRIPTOR,
                CreateWidgetRequest::Wait,
                expired.view(
                    Instant::now()
                        .checked_sub(Duration::from_millis(1))
                        .expect("one millisecond is representable"),
                ),
            )
            .await
            .expect("expired deadline is a closed outcome"),
        DispatchOutcome::DeadlineExceeded
    );

    let in_flight = ContextFixture::new(false);
    let cancel = async {
        tokio::task::yield_now().await;
        in_flight.cancellation.cancel();
    };
    let dispatch = dispatcher.dispatch::<CreateWidget>(
        &CreateWidget::DESCRIPTOR,
        CreateWidgetRequest::Wait,
        in_flight.view(Instant::now() + Duration::from_secs(1)),
    );
    let (outcome, ()) = tokio::join!(dispatch, cancel);
    assert_eq!(
        outcome.expect("in-flight cancel is a closed outcome"),
        DispatchOutcome::Cancelled
    );
}

#[tokio::test]
async fn draining_and_stopped_hosts_reject_new_admission() {
    let host = Arc::new(TestHost::new(AdmissionState::Ready));
    let dispatcher = dispatcher(host.clone());
    let fixture = ContextFixture::new(false);
    for (state, expected) in [
        (AdmissionState::Draining, DispatchError::HostDraining),
        (AdmissionState::Stopped, DispatchError::HostStopped),
    ] {
        host.set(state);
        assert_eq!(
            dispatcher
                .dispatch::<CreateWidget>(
                    &CreateWidget::DESCRIPTOR,
                    CreateWidgetRequest::Create {
                        name: "rejected".to_owned(),
                    },
                    fixture.view(Instant::now() + Duration::from_secs(1)),
                )
                .await,
            Err(expected)
        );
    }
}
