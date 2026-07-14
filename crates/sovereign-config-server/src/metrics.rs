use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy, Debug)]
pub(crate) enum AuthenticationResult {
    Success,
    MissingBearer,
    MalformedBearer,
    WrongAlgorithm,
    Inactive,
    InvalidClaims,
    Unavailable,
}

impl AuthenticationResult {
    const ALL: [Self; 7] = [
        Self::Success,
        Self::MissingBearer,
        Self::MalformedBearer,
        Self::WrongAlgorithm,
        Self::Inactive,
        Self::InvalidClaims,
        Self::Unavailable,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn outcome(self) -> &'static str {
        match self {
            Self::Success => "success",
            _ => "failure",
        }
    }

    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::Success => "accepted",
            Self::MissingBearer => "missing_bearer",
            Self::MalformedBearer => "malformed_bearer",
            Self::WrongAlgorithm => "wrong_algorithm",
            Self::Inactive => "inactive",
            Self::InvalidClaims => "invalid_claims",
            Self::Unavailable => "dependency_unavailable",
        }
    }
}

#[derive(Default)]
pub(crate) struct AuthenticationMetrics {
    counters: [AtomicU64; AuthenticationResult::ALL.len()],
}

impl AuthenticationMetrics {
    pub(crate) fn increment(&self, result: AuthenticationResult) {
        self.counters[result.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn render(&self) -> String {
        let mut output = String::from(
            "# HELP sovereign_config_authentication_total Protected gRPC authentication results.\n\
             # TYPE sovereign_config_authentication_total counter\n",
        );
        for result in AuthenticationResult::ALL {
            let value = self.counters[result.index()].load(Ordering::Relaxed);
            writeln!(
                output,
                "sovereign_config_authentication_total{{outcome=\"{}\",reason=\"{}\"}} {value}",
                result.outcome(),
                result.reason(),
            )
            .expect("writing metrics to a String cannot fail");
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticationMetrics, AuthenticationResult};

    #[test]
    fn metrics_use_only_bounded_result_labels() {
        let metrics = AuthenticationMetrics::default();
        metrics.increment(AuthenticationResult::Success);
        metrics.increment(AuthenticationResult::InvalidClaims);
        let rendered = metrics.render();

        assert!(rendered.contains("outcome=\"success\",reason=\"accepted\"} 1"));
        assert!(rendered.contains("outcome=\"failure\",reason=\"invalid_claims\"} 1"));
        assert_eq!(
            rendered
                .matches("sovereign_config_authentication_total{")
                .count(),
            7
        );
    }
}
