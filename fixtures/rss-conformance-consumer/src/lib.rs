#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use rss_conformance::{
        ConformanceErrorCategory,
        localtx::{
            ClassifiedError, CommitCase, CommitUnknownCase, NoWriteRejection, RejectedNoWriteCase,
            RollbackCase, RollbackFailedCase, assert_commit, assert_commit_unknown_no_replay,
            assert_rejected_no_write, assert_rollback, assert_rollback_failed_no_replay,
        },
    };
    use std::cell::Cell;

    struct ProviderError;
    fn error(category: ConformanceErrorCategory) -> ClassifiedError<ProviderError> {
        ClassifiedError::new(category, ProviderError)
    }

    #[tokio::test]
    async fn candidate_localtx_surface_runs_all_five_behaviors() {
        let writes = Cell::new(0_u32);
        assert_commit(CommitCase::new(
            || async {
                writes.set(1);
                Ok::<_, ClassifiedError<ProviderError>>(())
            },
            || async { Ok::<_, ClassifiedError<ProviderError>>(writes.get()) },
            1,
            || writes.get() as usize,
        ))
        .await
        .expect("commit");
        assert_rollback(RollbackCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Conflict)) },
            ConformanceErrorCategory::Conflict,
            || async { Ok::<_, ClassifiedError<ProviderError>>(0_u8) },
            0,
        ))
        .await
        .expect("rollback");
        assert_rejected_no_write(RejectedNoWriteCase::new(
            || async { Err::<(), _>(error(ConformanceErrorCategory::Authorization)) },
            NoWriteRejection::Authorization,
            || async { Ok::<_, ClassifiedError<ProviderError>>(0_u8) },
            0,
            || 0,
        ))
        .await
        .expect("rejected no-write");
        let commit_attempts = Cell::new(0_usize);
        assert_commit_unknown_no_replay(CommitUnknownCase::new(
            || async {
                commit_attempts.set(commit_attempts.get() + 1);
                Err::<(), _>(error(ConformanceErrorCategory::CommitUnknown))
            },
            || commit_attempts.get(),
        ))
        .await
        .expect("commit unknown");
        let rollback_attempts = Cell::new(0_usize);
        assert_rollback_failed_no_replay(RollbackFailedCase::new(
            || async {
                rollback_attempts.set(rollback_attempts.get() + 1);
                Err::<(), _>(error(ConformanceErrorCategory::RollbackFailed))
            },
            || rollback_attempts.get(),
        ))
        .await
        .expect("rollback failed");
    }
}
