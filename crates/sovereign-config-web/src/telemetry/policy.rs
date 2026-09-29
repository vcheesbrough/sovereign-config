//! What the page does with each answer from the ingest.
//!
//! Failing to reach the ingest is normal, and the answer to all of it is the
//! same: drop, carry on, and never try harder than the crowd can afford
//! (`client-export.md`, *Failure is normal*). Kept free of the browser so every
//! rule here is a plain unit test.

/// How one export attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// `2xx`. `rejected` is the partial-success count the ingest reported.
    Accepted { rejected: u64 },
    /// Any other HTTP status, with `Retry-After` in seconds when it came.
    Status {
        status: u16,
        retry_after_seconds: Option<u32>,
    },
    /// No response at all: offline, blocked, or the ingest is not there.
    Unreachable,
}

/// What to do next with the batch that produced the outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Next {
    /// Sent; move on to the next batch.
    Done,
    /// Wait this many milliseconds, then send the same batch again.
    RetryAfter(u32),
    /// Refresh the access token, then send the same batch again, once.
    RefreshThenRetry,
    /// Give this batch up.
    Drop,
    /// Give this batch, and every later one, up: telemetry is off for the
    /// rest of this page's life.
    Stop,
}

/// A change worth one console line. The page logs transitions, never
/// batches: a line per dropped batch would flood the tool someone would use
/// to debug the page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    FirstFailure(Outcome),
    Recovered,
    PartiallyRejected(u64),
    GaveUp(Outcome),
}

/// Retries of one batch after its first attempt, for the retryable answers.
pub(crate) const MAX_RETRIES: u32 = 3;
/// Batches given up in a row before the page stops for the session.
pub(crate) const MAX_ABANDONED_BATCHES: u32 = 3;
const BASE_DELAY_MS: u32 = 1_000;
const MAX_DELAY_MS: u32 = 30_000;
const MAX_RETRY_AFTER_SECONDS: u32 = 60;

/// Whether export is working, failing, or has given up for the session.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Health {
    #[default]
    Working,
    Failing,
    Stopped,
}

#[derive(Default)]
pub(crate) struct Policy {
    health: Health,
    refreshed_after_401: bool,
    retries: u32,
    abandoned: u32,
    reported_partial: bool,
}

impl Policy {
    pub(crate) fn stopped(&self) -> bool {
        self.health == Health::Stopped
    }

    /// Decides what follows `outcome`. `jitter` is uniform in `[0, 1)` and
    /// spreads a fleet of pages that all failed at once.
    pub(crate) fn decide(&mut self, outcome: Outcome, jitter: f64) -> (Next, Option<Transition>) {
        if self.stopped() {
            return (Next::Stop, None);
        }
        match outcome {
            Outcome::Accepted { rejected } => {
                let recovered = std::mem::take(&mut self.health) == Health::Failing;
                self.refreshed_after_401 = false;
                self.retries = 0;
                self.abandoned = 0;
                let transition = if recovered {
                    Some(Transition::Recovered)
                } else if rejected > 0 && !self.reported_partial {
                    self.reported_partial = true;
                    Some(Transition::PartiallyRejected(rejected))
                } else {
                    None
                };
                (Next::Done, transition)
            }
            // Every refusal of the token is 401, so an expired token and a
            // misconfigured provider look alike: one refresh, and a second
            // refusal is permanent for the session.
            Outcome::Status { status: 401, .. } => {
                if self.refreshed_after_401 {
                    self.stop(outcome)
                } else {
                    self.refreshed_after_401 = true;
                    (Next::RefreshThenRetry, self.fail(outcome))
                }
            }
            Outcome::Status {
                status: 429 | 502 | 503 | 504,
                retry_after_seconds,
            } => self.retry(outcome, retry_after_seconds, jitter),
            // Nothing answered: the same as the ingest saying it is
            // unavailable, and just as worth one more try within the session.
            Outcome::Unreachable => self.retry(outcome, None, jitter),
            // 400, 403, 413, 500 and the rest are permanent for this payload.
            Outcome::Status { .. } => self.abandon(outcome),
        }
    }

    fn retry(
        &mut self,
        outcome: Outcome,
        retry_after_seconds: Option<u32>,
        jitter: f64,
    ) -> (Next, Option<Transition>) {
        if self.retries >= MAX_RETRIES {
            return self.abandon(outcome);
        }
        self.retries += 1;
        let delay = retry_after_seconds.map_or_else(
            || backoff(self.retries, jitter),
            |seconds| seconds.min(MAX_RETRY_AFTER_SECONDS) * 1_000,
        );
        (Next::RetryAfter(delay), self.fail(outcome))
    }

    fn abandon(&mut self, outcome: Outcome) -> (Next, Option<Transition>) {
        self.retries = 0;
        self.abandoned += 1;
        if self.abandoned >= MAX_ABANDONED_BATCHES {
            return self.stop(outcome);
        }
        (Next::Drop, self.fail(outcome))
    }

    fn stop(&mut self, outcome: Outcome) -> (Next, Option<Transition>) {
        self.health = Health::Stopped;
        (Next::Stop, Some(Transition::GaveUp(outcome)))
    }

    fn fail(&mut self, outcome: Outcome) -> Option<Transition> {
        (std::mem::replace(&mut self.health, Health::Failing) == Health::Working)
            .then_some(Transition::FirstFailure(outcome))
    }
}

/// Exponential from one second, capped at thirty, then jittered down to
/// between half and all of it.
fn backoff(retry: u32, jitter: f64) -> u32 {
    let full = BASE_DELAY_MS
        .saturating_mul(1 << retry.saturating_sub(1).min(16))
        .min(MAX_DELAY_MS);
    let factor = 0.5 + jitter.clamp(0.0, 1.0) / 2.0;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let jittered = (f64::from(full) * factor) as u32;
    jittered
}

#[cfg(test)]
mod tests {
    use super::{MAX_ABANDONED_BATCHES, MAX_RETRIES, Next, Outcome, Policy, Transition, backoff};

    const fn status(status: u16) -> Outcome {
        Outcome::Status {
            status,
            retry_after_seconds: None,
        }
    }

    const OK: Outcome = Outcome::Accepted { rejected: 0 };

    #[test]
    fn a_401_gets_one_refresh_then_stops_for_the_session() {
        let mut policy = Policy::default();
        let (next, transition) = policy.decide(status(401), 0.5);
        assert_eq!(next, Next::RefreshThenRetry);
        assert_eq!(transition, Some(Transition::FirstFailure(status(401))));
        let (next, transition) = policy.decide(status(401), 0.5);
        assert_eq!(next, Next::Stop);
        assert_eq!(transition, Some(Transition::GaveUp(status(401))));
        assert!(policy.stopped());
        assert_eq!(
            policy.decide(OK, 0.5),
            (Next::Stop, None),
            "stopped is final"
        );
    }

    #[test]
    fn a_refreshed_token_that_works_resets_the_refresh_budget() {
        let mut policy = Policy::default();
        assert_eq!(policy.decide(status(401), 0.5).0, Next::RefreshThenRetry);
        assert_eq!(
            policy.decide(OK, 0.5),
            (Next::Done, Some(Transition::Recovered))
        );
        assert_eq!(policy.decide(status(401), 0.5).0, Next::RefreshThenRetry);
    }

    /// Only 429, 502, 503 and 504 (and no answer at all) are retried.
    #[test]
    fn only_the_four_retryable_statuses_retry() {
        for code in 100..=599 {
            if (200..300).contains(&code) {
                continue;
            }
            let mut policy = Policy::default();
            let (next, _) = policy.decide(status(code), 0.5);
            match code {
                429 | 502 | 503 | 504 => assert!(matches!(next, Next::RetryAfter(_)), "{code}"),
                401 => assert_eq!(next, Next::RefreshThenRetry),
                _ => assert_eq!(next, Next::Drop, "{code} is permanent for the payload"),
            }
        }
        let mut policy = Policy::default();
        assert!(matches!(
            policy.decide(Outcome::Unreachable, 0.5).0,
            Next::RetryAfter(_)
        ));
    }

    #[test]
    fn retries_are_capped_then_the_batch_is_dropped() {
        let mut policy = Policy::default();
        for _ in 0..MAX_RETRIES {
            assert!(matches!(
                policy.decide(status(503), 0.5).0,
                Next::RetryAfter(_)
            ));
        }
        assert_eq!(policy.decide(status(503), 0.5).0, Next::Drop);
    }

    #[test]
    fn repeated_abandoned_batches_stop_the_session() {
        let mut policy = Policy::default();
        for batch in 1..=MAX_ABANDONED_BATCHES {
            let next = policy.decide(status(400), 0.5).0;
            if batch < MAX_ABANDONED_BATCHES {
                assert_eq!(next, Next::Drop);
            } else {
                assert_eq!(next, Next::Stop);
            }
        }
        assert!(policy.stopped());
    }

    #[test]
    fn retry_after_is_honoured_and_capped() {
        let mut policy = Policy::default();
        let answer = |seconds| Outcome::Status {
            status: 429,
            retry_after_seconds: Some(seconds),
        };
        assert_eq!(policy.decide(answer(7), 0.5).0, Next::RetryAfter(7_000));
        assert_eq!(
            policy.decide(answer(3_600), 0.5).0,
            Next::RetryAfter(60_000)
        );
    }

    #[test]
    fn backoff_grows_is_capped_and_jittered() {
        assert_eq!(backoff(1, 1.0), 1_000);
        assert_eq!(backoff(2, 1.0), 2_000);
        assert_eq!(backoff(3, 1.0), 4_000);
        assert_eq!(backoff(20, 1.0), 30_000);
        assert_eq!(backoff(1, 0.0), 500);
        assert!((500..=1_000).contains(&backoff(1, 0.37)));
    }

    /// One line for the first failure, none while it stays failed, one on
    /// recovery.
    #[test]
    fn transitions_are_reported_once_each() {
        let mut policy = Policy::default();
        assert_eq!(policy.decide(OK, 0.5).1, None);
        assert_eq!(
            policy.decide(Outcome::Unreachable, 0.5).1,
            Some(Transition::FirstFailure(Outcome::Unreachable))
        );
        assert_eq!(policy.decide(Outcome::Unreachable, 0.5).1, None);
        assert_eq!(policy.decide(status(503), 0.5).1, None);
        assert_eq!(policy.decide(OK, 0.5).1, Some(Transition::Recovered));
        assert_eq!(policy.decide(OK, 0.5).1, None);
    }

    #[test]
    fn a_partial_rejection_is_reported_once() {
        let mut policy = Policy::default();
        let partial = Outcome::Accepted { rejected: 2 };
        assert_eq!(
            policy.decide(partial, 0.5),
            (Next::Done, Some(Transition::PartiallyRejected(2)))
        );
        assert_eq!(policy.decide(partial, 0.5), (Next::Done, None));
    }
}
