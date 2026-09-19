use std::{
    fmt::Write as _,
    sync::atomic::{AtomicU64, Ordering},
};

/// The bucket a request counts against when its route names no protocol version
/// this server recognises — a health probe, a gRPC reflection call, or a path
/// that is simply not ours.
pub(crate) const UNRECOGNISED_PROTOCOL_LABEL: &str = "unrecognised";

/// Per-protocol-version request counts.
///
/// This is the input to the retirement decision: a protocol version may not be
/// removed until its counter has read zero across an observation window, since
/// clients have no fallback and the provider does not cache. Counting at
/// `GetVersion` would not answer that question — negotiation happens once at
/// connect, so a long-lived provider would register a single connect and then
/// go quiet while its traffic continued.
///
/// The label domain is fixed at construction from compiled-in strings and is
/// never taken from a request, so no route path can widen it. Anything outside
/// that domain lands in [`UNRECOGNISED_PROTOCOL_LABEL`].
pub(crate) struct ProtocolMetrics {
    versions: Vec<(&'static str, AtomicU64)>,
    unrecognised: AtomicU64,
}

impl ProtocolMetrics {
    /// Counters for exactly `versions`, which must be compiled-in labels.
    pub(crate) fn new(versions: &[&'static str]) -> Self {
        Self {
            versions: versions
                .iter()
                .map(|label| (*label, AtomicU64::new(0)))
                .collect(),
            unrecognised: AtomicU64::new(0),
        }
    }

    /// Counts one request against `version`, or against the unrecognised bucket
    /// when it is not a label this instance was built with.
    pub(crate) fn record(&self, version: &str) {
        match self
            .versions
            .iter()
            .find(|(label, _)| *label == version)
            .map(|(_, counter)| counter)
        {
            Some(counter) => counter.fetch_add(1, Ordering::Relaxed),
            None => self.unrecognised.fetch_add(1, Ordering::Relaxed),
        };
    }

    pub(crate) fn render(&self) -> String {
        let mut output = String::from(
            "# HELP sovereign_config_protocol_requests_total gRPC requests by protocol version.\n\
             # TYPE sovereign_config_protocol_requests_total counter\n",
        );
        for (label, counter) in &self.versions {
            let value = counter.load(Ordering::Relaxed);
            writeln!(
                output,
                "sovereign_config_protocol_requests_total{{version=\"{label}\"}} {value}",
            )
            .expect("writing metrics to a String cannot fail");
        }
        let value = self.unrecognised.load(Ordering::Relaxed);
        writeln!(
            output,
            "sovereign_config_protocol_requests_total{{version=\"{UNRECOGNISED_PROTOCOL_LABEL}\"}} {value}",
        )
        .expect("writing metrics to a String cannot fail");
        output
    }
}

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

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedOperation {
    List,
    Create,
    Rotate,
    Revoke,
}

impl ManagedOperation {
    const ALL: [Self; 4] = [Self::List, Self::Create, Self::Rotate, Self::Revoke];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Create => "create",
            Self::Rotate => "rotate",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedOperationResult {
    Success,
    InvalidRequest,
    Unauthenticated,
    PermissionDenied,
    NotFound,
    Conflict,
    Storage,
    Dependency,
    CleanupRequired,
    Internal,
}

impl ManagedOperationResult {
    const ALL: [Self; 10] = [
        Self::Success,
        Self::InvalidRequest,
        Self::Unauthenticated,
        Self::PermissionDenied,
        Self::NotFound,
        Self::Conflict,
        Self::Storage,
        Self::Dependency,
        Self::CleanupRequired,
        Self::Internal,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InvalidRequest => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Storage => "storage_unavailable",
            Self::Dependency => "dependency_failed",
            Self::CleanupRequired => "cleanup_required",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedDependencyCall {
    CreateAccount,
    SetAttributes,
    FindUser,
    FindCredentials,
    SetCredential,
    DeleteUser,
    /// Best-effort: never fails or rolls back connection creation.
    AssignGroup,
}

impl ManagedDependencyCall {
    const ALL: [Self; 7] = [
        Self::CreateAccount,
        Self::SetAttributes,
        Self::FindUser,
        Self::FindCredentials,
        Self::SetCredential,
        Self::DeleteUser,
        Self::AssignGroup,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CreateAccount => "create_account",
            Self::SetAttributes => "set_attributes",
            Self::FindUser => "find_user",
            Self::FindCredentials => "find_credentials",
            Self::SetCredential => "set_credential",
            Self::DeleteUser => "delete_user",
            Self::AssignGroup => "assign_group",
        }
    }
}

/// Fixed dependency outcomes: `ok` plus the bounded [`crate::authentik::AdminError`] kinds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ManagedDependencyOutcome {
    Ok,
    NotFound,
    Rejected,
    Unavailable,
    Ambiguous,
    Invalid,
}

impl ManagedDependencyOutcome {
    const ALL: [Self; 6] = [
        Self::Ok,
        Self::NotFound,
        Self::Rejected,
        Self::Unavailable,
        Self::Ambiguous,
        Self::Invalid,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
            Self::Ambiguous => "ambiguous",
            Self::Invalid => "invalid",
        }
    }
}

/// Bounded managed-connection operation and dependency counters.
///
/// Labels are fixed enums only: no connection identifier, name, root, username,
/// credential, URL, or provider response detail can reach a label value.
#[derive(Default)]
pub(crate) struct ManagedConnectionMetrics {
    operations: [[AtomicU64; ManagedOperationResult::ALL.len()]; ManagedOperation::ALL.len()],
    dependencies:
        [[AtomicU64; ManagedDependencyOutcome::ALL.len()]; ManagedDependencyCall::ALL.len()],
}

impl ManagedConnectionMetrics {
    pub(crate) fn record_operation(
        &self,
        operation: ManagedOperation,
        result: ManagedOperationResult,
    ) {
        self.operations[operation.index()][result.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_dependency(
        &self,
        call: ManagedDependencyCall,
        outcome: ManagedDependencyOutcome,
    ) {
        self.dependencies[call.index()][outcome.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn render(&self) -> String {
        let mut output = String::from(
            "# HELP sovereign_config_managed_connection_operations_total Managed connection operation results.\n\
             # TYPE sovereign_config_managed_connection_operations_total counter\n",
        );
        for operation in ManagedOperation::ALL {
            for result in ManagedOperationResult::ALL {
                let value =
                    self.operations[operation.index()][result.index()].load(Ordering::Relaxed);
                writeln!(
                    output,
                    "sovereign_config_managed_connection_operations_total{{operation=\"{}\",result=\"{}\"}} {value}",
                    operation.as_str(),
                    result.as_str(),
                )
                .expect("writing metrics to a String cannot fail");
            }
        }
        output.push_str(
            "# HELP sovereign_config_managed_dependency_total Managed connection Authentik dependency outcomes.\n\
             # TYPE sovereign_config_managed_dependency_total counter\n",
        );
        for call in ManagedDependencyCall::ALL {
            for outcome in ManagedDependencyOutcome::ALL {
                let value =
                    self.dependencies[call.index()][outcome.index()].load(Ordering::Relaxed);
                writeln!(
                    output,
                    "sovereign_config_managed_dependency_total{{call=\"{}\",outcome=\"{}\"}} {value}",
                    call.as_str(),
                    outcome.as_str(),
                )
                .expect("writing metrics to a String cannot fail");
            }
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthenticationMetrics, AuthenticationResult, ManagedConnectionMetrics,
        ManagedDependencyCall, ManagedDependencyOutcome, ManagedOperation, ManagedOperationResult,
    };

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

    #[test]
    fn managed_metrics_use_only_bounded_fixed_labels() {
        let metrics = ManagedConnectionMetrics::default();
        metrics.record_operation(ManagedOperation::Create, ManagedOperationResult::Success);
        metrics.record_dependency(
            ManagedDependencyCall::SetCredential,
            ManagedDependencyOutcome::Ambiguous,
        );
        let rendered = metrics.render();

        assert!(rendered.contains(
            "sovereign_config_managed_connection_operations_total{operation=\"create\",result=\"success\"} 1"
        ));
        assert!(rendered.contains(
            "sovereign_config_managed_dependency_total{call=\"set_credential\",outcome=\"ambiguous\"} 1"
        ));
        assert_eq!(
            rendered
                .matches("sovereign_config_managed_connection_operations_total{")
                .count(),
            40
        );
        assert_eq!(
            rendered
                .matches("sovereign_config_managed_dependency_total{")
                .count(),
            42
        );
    }
}
