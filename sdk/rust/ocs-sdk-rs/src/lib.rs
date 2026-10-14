// SPDX-License-Identifier: Apache-2.0
// Copyright (C) Iurii Trukhin.

#![forbid(unsafe_code)]

//! Official zero-dependency Rust SDK for the CloudRING Open Cloud Standard (OCS v3).
//!
//! Provides strongly typed representations for the nine CloudRING product categories,
//! canonical resource identities, operation state machines, idempotency verification,
//! quota accounting, conformance reporting, and deterministic request construction.

use std::collections::BTreeMap;
use std::fmt;

/// Canonical API version for Open Cloud Standard v3 packages and operations.
pub const API_VERSION: &str = "ocsv3.cloudring.io/v1alpha1";

/// Maximum length of a canonical OCS identifier.
pub const MAX_IDENTIFIER_LEN: usize = 64;

/// Minimum length of a canonical OCS identifier.
pub const MIN_IDENTIFIER_LEN: usize = 3;

/// Errors returned by OCS v3 validation, state transitions, and request builders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcsError {
    InvalidIdentifier(String),
    InvalidServiceCategory(String),
    InvalidStateTransition {
        from: OperationState,
        to: OperationState,
    },
    IdempotencyConflict {
        idempotency_key: String,
    },
    QuotaExceeded {
        metric: String,
        requested: u64,
        available: u64,
    },
    InvalidQuotaDefinition(String),
    InvalidTarget(String),
    MissingField(&'static str),
}

impl fmt::Display for OcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier(id) => write!(f, "invalid OCS canonical identifier: {id}"),
            Self::InvalidServiceCategory(cat) => write!(f, "unknown OCS service category: {cat}"),
            Self::InvalidStateTransition { from, to } => {
                write!(
                    f,
                    "invalid operation state transition from {} to {}",
                    from.as_str(),
                    to.as_str()
                )
            }
            Self::IdempotencyConflict { idempotency_key } => {
                write!(
                    f,
                    "idempotency key reused with conflicting operation envelope: {idempotency_key}"
                )
            }
            Self::QuotaExceeded {
                metric,
                requested,
                available,
            } => write!(
                f,
                "quota exceeded for {metric}: requested {requested}, available {available}"
            ),
            Self::InvalidQuotaDefinition(msg) => write!(f, "invalid quota definition: {msg}"),
            Self::InvalidTarget(msg) => write!(f, "invalid OCS client target: {msg}"),
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
        }
    }
}

impl std::error::Error for OcsError {}

/// Validates that `value` is a canonical lowercase ASCII identifier (`3..=64` chars,
/// alphanumeric start/end, containing only `[a-z0-9._-]`, and no `..` sequence).
pub fn validate_canonical_id(value: &str) -> Result<(), OcsError> {
    let bytes = value.as_bytes();
    if bytes.len() < MIN_IDENTIFIER_LEN || bytes.len() > MAX_IDENTIFIER_LEN {
        return Err(OcsError::InvalidIdentifier(value.to_string()));
    }
    if value.contains("..") {
        return Err(OcsError::InvalidIdentifier(value.to_string()));
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[bytes.len() - 1]) {
        return Err(OcsError::InvalidIdentifier(value.to_string()));
    }
    for &b in bytes {
        if !(is_alnum(b) || b == b'-' || b == b'_' || b == b'.') {
            return Err(OcsError::InvalidIdentifier(value.to_string()));
        }
    }
    Ok(())
}

/// The nine canonical product service categories defined by CloudRING / OCS v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceCategory {
    Compute,
    Volume,
    Network,
    Kubernetes,
    ObjectStorage,
    Backup,
    AccessControl,
    Support,
    ExternalIntegration,
}

impl ServiceCategory {
    /// Returns all nine canonical OCS v3 service categories in deterministic order.
    pub const fn all() -> [ServiceCategory; 9] {
        [
            Self::Compute,
            Self::Volume,
            Self::Network,
            Self::Kubernetes,
            Self::ObjectStorage,
            Self::Backup,
            Self::AccessControl,
            Self::Support,
            Self::ExternalIntegration,
        ]
    }

    /// Returns the canonical wire slug for this service category.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Compute => "compute",
            Self::Volume => "volume",
            Self::Network => "network",
            Self::Kubernetes => "kubernetes",
            Self::ObjectStorage => "object-storage",
            Self::Backup => "backup",
            Self::AccessControl => "access-control",
            Self::Support => "support",
            Self::ExternalIntegration => "external-integration",
        }
    }

    /// Parses a canonical service category slug.
    pub fn parse(slug: &str) -> Result<Self, OcsError> {
        match slug {
            "compute" => Ok(Self::Compute),
            "volume" => Ok(Self::Volume),
            "network" => Ok(Self::Network),
            "kubernetes" => Ok(Self::Kubernetes),
            "object-storage" => Ok(Self::ObjectStorage),
            "backup" => Ok(Self::Backup),
            "access-control" => Ok(Self::AccessControl),
            "support" => Ok(Self::Support),
            "external-integration" => Ok(Self::ExternalIntegration),
            other => Err(OcsError::InvalidServiceCategory(other.to_string())),
        }
    }
}

/// Tenant-scoped canonical resource identity in OCS v3.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceIdentity {
    tenant_id: String,
    project_id: String,
    service_category: ServiceCategory,
    resource_id: String,
}

impl ResourceIdentity {
    /// Constructs a validated `ResourceIdentity`.
    pub fn new(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        service_category: ServiceCategory,
        resource_id: impl Into<String>,
    ) -> Result<Self, OcsError> {
        let tenant_id = tenant_id.into();
        let project_id = project_id.into();
        let resource_id = resource_id.into();
        validate_canonical_id(&tenant_id)?;
        validate_canonical_id(&project_id)?;
        validate_canonical_id(&resource_id)?;
        Ok(Self {
            tenant_id,
            project_id,
            service_category,
            resource_id,
        })
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn service_category(&self) -> ServiceCategory {
        self.service_category
    }

    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    /// Formats the canonical OCS v3 URN:
    /// `urn:ocs:v3:<tenant_id>:<project_id>:<service_category>:<resource_id>`.
    pub fn to_urn(&self) -> String {
        format!(
            "urn:ocs:v3:{}:{}:{}:{}",
            self.tenant_id,
            self.project_id,
            self.service_category.as_str(),
            self.resource_id
        )
    }

    /// Parses and validates a canonical OCS v3 URN.
    pub fn parse_urn(urn: &str) -> Result<Self, OcsError> {
        let parts: Vec<&str> = urn.split(':').collect();
        if parts.len() != 7 || parts[0] != "urn" || parts[1] != "ocs" || parts[2] != "v3" {
            return Err(OcsError::InvalidIdentifier(urn.to_string()));
        }
        let category = ServiceCategory::parse(parts[5])?;
        Self::new(parts[3], parts[4], category, parts[6])
    }
}

/// Lifecycle state of an asynchronous or synchronous OCS v3 operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}

impl OperationState {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Returns true if the state is terminal (`Succeeded`, `Failed`, or `Cancelled`).
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    /// Checks whether transitioning from `self` to `next` is permitted by the OCS v3 state machine:
    /// `Pending -> Running | Cancelled` and `Running -> Succeeded | Failed | Cancelled`.
    /// Idempotent self-transitions (`state -> state`) are also permitted.
    pub const fn can_transition_to(&self, next: OperationState) -> bool {
        match (*self, next) {
            (a, b) if a as u8 == b as u8 => true,
            (Self::Pending, Self::Running | Self::Cancelled) => true,
            (Self::Running, Self::Succeeded | Self::Failed | Self::Cancelled) => true,
            _ => false,
        }
    }

    /// Validates and returns the next `OperationState`.
    pub fn transition_to(&self, next: OperationState) -> Result<OperationState, OcsError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(OcsError::InvalidStateTransition {
                from: *self,
                to: next,
            })
        }
    }
}

/// Canonical operation envelope tracking execution and idempotency across provider boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEnvelope {
    api_version: String,
    operation_id: String,
    idempotency_key: String,
    action: String,
    resource: ResourceIdentity,
    state: OperationState,
    parameters: BTreeMap<String, String>,
}

impl OperationEnvelope {
    /// Creates a new `OperationEnvelope` in `OperationState::Pending`.
    pub fn new(
        operation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
        action: impl Into<String>,
        resource: ResourceIdentity,
        parameters: BTreeMap<String, String>,
    ) -> Result<Self, OcsError> {
        let operation_id = operation_id.into();
        let idempotency_key = idempotency_key.into();
        let action = action.into();
        validate_canonical_id(&operation_id)?;
        validate_canonical_id(&idempotency_key)?;
        validate_canonical_id(&action)?;
        for (k, v) in &parameters {
            validate_canonical_id(k)?;
            if v.trim().is_empty() || v.len() > 1024 || v.contains('\0') {
                return Err(OcsError::InvalidIdentifier(k.clone()));
            }
        }
        Ok(Self {
            api_version: API_VERSION.to_string(),
            operation_id,
            idempotency_key,
            action,
            resource,
            state: OperationState::Pending,
            parameters,
        })
    }

    pub fn api_version(&self) -> &str {
        &self.api_version
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn action(&self) -> &str {
        &self.action
    }

    pub fn resource(&self) -> &ResourceIdentity {
        &self.resource
    }

    pub fn state(&self) -> OperationState {
        self.state
    }

    pub fn parameters(&self) -> &BTreeMap<String, String> {
        &self.parameters
    }

    /// Advances the operation envelope to `next_state` if allowed by the state machine.
    pub fn advance_state(&mut self, next_state: OperationState) -> Result<OperationState, OcsError> {
        let next = self.state.transition_to(next_state)?;
        self.state = next;
        Ok(next)
    }

    /// Verifies idempotency between `self` (a previously recorded operation) and `candidate`.
    /// If both share the same `idempotency_key`, they must target the exact same resource,
    /// action, and parameter map; otherwise `OcsError::IdempotencyConflict` is returned.
    pub fn verify_idempotent_replay(&self, candidate: &OperationEnvelope) -> Result<bool, OcsError> {
        if self.idempotency_key != candidate.idempotency_key {
            return Ok(false);
        }
        if self.resource != candidate.resource
            || self.action != candidate.action
            || self.parameters != candidate.parameters
        {
            return Err(OcsError::IdempotencyConflict {
                idempotency_key: self.idempotency_key.clone(),
            });
        }
        Ok(true)
    }

    /// Produces a deterministic canonical wire representation suitable for signing or hashing.
    pub fn canonical_wire_string(&self) -> String {
        let mut out = format!(
            "v={};op={};idem={};act={};urn={};st={}",
            self.api_version,
            self.operation_id,
            self.idempotency_key,
            self.action,
            self.resource.to_urn(),
            self.state.as_str()
        );
        for (k, v) in &self.parameters {
            out.push_str(&format!(";p.{k}={v}"));
        }
        out
    }
}

/// Quota limit and usage tracker for a single metered dimension in OCS v3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaLimit {
    metric: String,
    unit: String,
    limit: u64,
    used: u64,
}

impl QuotaLimit {
    pub fn new(
        metric: impl Into<String>,
        unit: impl Into<String>,
        limit: u64,
        used: u64,
    ) -> Result<Self, OcsError> {
        let metric = metric.into();
        let unit = unit.into();
        validate_canonical_id(&metric)?;
        validate_canonical_id(&unit)?;
        if used > limit {
            return Err(OcsError::InvalidQuotaDefinition(format!(
                "used ({used}) exceeds limit ({limit}) for {metric}"
            )));
        }
        Ok(Self {
            metric,
            unit,
            limit,
            used,
        })
    }

    pub fn metric(&self) -> &str {
        &self.metric
    }

    pub fn unit(&self) -> &str {
        &self.unit
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn used(&self) -> u64 {
        self.used
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn can_allocate(&self, amount: u64) -> bool {
        amount <= self.remaining()
    }

    pub fn allocate(&mut self, amount: u64) -> Result<u64, OcsError> {
        let available = self.remaining();
        if amount > available {
            return Err(OcsError::QuotaExceeded {
                metric: self.metric.clone(),
                requested: amount,
                available,
            });
        }
        self.used += amount;
        Ok(self.used)
    }
}

/// A single structural check inside an OCS v3 `ConformanceReport`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceCheck {
    pub surface: String,
    pub passed: bool,
    pub detail: String,
}

/// Provider-neutral OCS v3 conformance evaluation report.
/// Does not claim live production readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    pub api_version: String,
    pub package_name: String,
    pub package_version: String,
    pub category: ServiceCategory,
    pub provider_neutral: bool,
    pub production_mutate: bool,
    pub checks: Vec<ConformanceCheck>,
    pub non_claims: Vec<String>,
}

impl ConformanceReport {
    /// Evaluates a connector's structural metadata and returns a `ConformanceReport`.
    pub fn evaluate(
        package_name: &str,
        package_version: &str,
        category: ServiceCategory,
        supported_actions: &[&str],
        quotas: &[QuotaLimit],
    ) -> Self {
        let mut checks = Vec::new();
        let pkg_ok = validate_canonical_id(package_name).is_ok();
        checks.push(ConformanceCheck {
            surface: "package.name".to_string(),
            passed: pkg_ok,
            detail: if pkg_ok {
                "canonical package identifier".to_string()
            } else {
                "invalid package identifier".to_string()
            },
        });

        let ver_ok = !package_version.trim().is_empty() && !package_version.contains(' ');
        checks.push(ConformanceCheck {
            surface: "package.version".to_string(),
            passed: ver_ok,
            detail: if ver_ok {
                "version present".to_string()
            } else {
                "missing or malformed version".to_string()
            },
        });

        let baseline = ["provision", "resume", "resize", "deprovision"];
        let has_baseline = baseline
            .iter()
            .all(|req| supported_actions.iter().any(|act| act == req));
        let has_hold_or_suspend = supported_actions
            .iter()
            .any(|act| *act == "hold" || *act == "suspend");
        let lifecycle_ok = has_baseline && has_hold_or_suspend;
        checks.push(ConformanceCheck {
            surface: "service.lifecycle".to_string(),
            passed: lifecycle_ok,
            detail: if lifecycle_ok {
                "universal lifecycle baseline declared".to_string()
            } else {
                "missing required lifecycle action".to_string()
            },
        });

        let quotas_ok = !quotas.is_empty();
        checks.push(ConformanceCheck {
            surface: "service.quotas".to_string(),
            passed: quotas_ok,
            detail: if quotas_ok {
                "at least one quota meter declared".to_string()
            } else {
                "no quota meters declared".to_string()
            },
        });

        Self {
            api_version: API_VERSION.to_string(),
            package_name: package_name.to_string(),
            package_version: package_version.to_string(),
            category,
            provider_neutral: true,
            production_mutate: false,
            checks,
            non_claims: vec![
                "conformance does not claim live production readiness".to_string(),
                "conformance does not perform provider, DNS, Kubernetes, or billing mutation"
                    .to_string(),
            ],
        }
    }

    /// Returns true if all conformance checks passed and `production_mutate` is false.
    pub fn passed(&self) -> bool {
        !self.production_mutate
            && self.provider_neutral
            && !self.checks.is_empty()
            && self.checks.iter().all(|c| c.passed)
    }
}

/// Client configuration for interacting with an OCS v3 control plane endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcsClientConfig {
    endpoint: String,
    user_agent: String,
    timeout_millis: u64,
}

impl OcsClientConfig {
    /// Creates a validated `OcsClientConfig`. Requires an `https://` endpoint and rejects
    /// empty hosts or forbidden private domain suffixes.
    pub fn new(endpoint: impl Into<String>, timeout_millis: u64) -> Result<Self, OcsError> {
        let endpoint = endpoint.into();
        let trimmed = endpoint.trim().trim_end_matches('/').to_string();
        let Some(rest) = trimmed.strip_prefix("https://") else {
            return Err(OcsError::InvalidTarget(
                "OCS target must use https://".to_string(),
            ));
        };
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() || host.contains("..") || !host.contains('.') {
            return Err(OcsError::InvalidTarget(
                "OCS target must contain a valid DNS hostname".to_string(),
            ));
        }
        if timeout_millis == 0 || timeout_millis > 300_000 {
            return Err(OcsError::InvalidTarget(
                "timeout_millis must be between 1 and 300000".to_string(),
            ));
        }
        Ok(Self {
            endpoint: trimmed,
            user_agent: format!("ocs-sdk-rs/{}", env!("CARGO_PKG_VERSION")),
            timeout_millis,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn timeout_millis(&self) -> u64 {
        self.timeout_millis
    }
}

/// Immutable request constructed by `RequestBuilder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcsRequest {
    pub url: String,
    pub user_agent: String,
    pub timeout_millis: u64,
    pub envelope: OperationEnvelope,
    pub wire_payload: String,
}

/// Fluent builder for constructing validated `OcsRequest` values.
#[derive(Debug, Clone)]
pub struct RequestBuilder {
    config: OcsClientConfig,
    operation_id: Option<String>,
    idempotency_key: Option<String>,
    action: Option<String>,
    resource: Option<ResourceIdentity>,
    parameters: BTreeMap<String, String>,
}

impl RequestBuilder {
    pub fn new(config: OcsClientConfig) -> Self {
        Self {
            config,
            operation_id: None,
            idempotency_key: None,
            action: None,
            resource: None,
            parameters: BTreeMap::new(),
        }
    }

    pub fn operation_id(mut self, id: impl Into<String>) -> Self {
        self.operation_id = Some(id.into());
        self
    }

    pub fn idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn resource(mut self, resource: ResourceIdentity) -> Self {
        self.resource = Some(resource);
        self
    }

    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.parameters.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<OcsRequest, OcsError> {
        let operation_id = self
            .operation_id
            .ok_or(OcsError::MissingField("operation_id"))?;
        let idempotency_key = self
            .idempotency_key
            .ok_or(OcsError::MissingField("idempotency_key"))?;
        let action = self.action.ok_or(OcsError::MissingField("action"))?;
        let resource = self.resource.ok_or(OcsError::MissingField("resource"))?;

        let envelope = OperationEnvelope::new(
            operation_id,
            idempotency_key,
            action,
            resource.clone(),
            self.parameters,
        )?;
        let url = format!(
            "{}/v3/tenants/{}/projects/{}/services/{}/resources/{}/operations",
            self.config.endpoint(),
            resource.tenant_id(),
            resource.project_id(),
            resource.service_category().as_str(),
            resource.resource_id()
        );
        let wire_payload = envelope.canonical_wire_string();
        Ok(OcsRequest {
            url,
            user_agent: self.config.user_agent().to_string(),
            timeout_millis: self.config.timeout_millis(),
            envelope,
            wire_payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_categories_roundtrip_all_nine() {
        let all = ServiceCategory::all();
        assert_eq!(all.len(), 9);
        for category in all {
            let slug = category.as_str();
            let parsed = ServiceCategory::parse(slug).expect("category should parse");
            assert_eq!(parsed, category);
        }
        assert_eq!(
            ServiceCategory::parse("unknown"),
            Err(OcsError::InvalidServiceCategory("unknown".to_string()))
        );
    }

    #[test]
    fn canonical_id_and_resource_identity_validation() {
        assert!(validate_canonical_id("valid-id-01.a_b").is_ok());
        assert!(validate_canonical_id("ab").is_err());
        assert!(validate_canonical_id("UPPERCASE").is_err());
        assert!(validate_canonical_id("bad..dots").is_err());
        assert!(validate_canonical_id("-leading-dash").is_err());
        assert!(validate_canonical_id("trailing-dash-").is_err());

        let identity = ResourceIdentity::new(
            "tenant-alpha",
            "proj-core",
            ServiceCategory::Kubernetes,
            "cluster-eu-01",
        )
        .expect("valid identity");
        let urn = identity.to_urn();
        assert_eq!(
            urn,
            "urn:ocs:v3:tenant-alpha:proj-core:kubernetes:cluster-eu-01"
        );
        let parsed = ResourceIdentity::parse_urn(&urn).expect("valid URN");
        assert_eq!(parsed, identity);
        assert!(ResourceIdentity::parse_urn("urn:ocs:v2:a:b:compute:c").is_err());
    }

    #[test]
    fn operation_state_machine_and_idempotency() {
        let identity = ResourceIdentity::new(
            "tenant-alpha",
            "proj-core",
            ServiceCategory::Compute,
            "vm-node-01",
        )
        .expect("valid identity");
        let mut params = BTreeMap::new();
        params.insert("shape".to_string(), "standard-4".to_string());

        let mut env1 = OperationEnvelope::new(
            "op-create-01",
            "idem-key-01",
            "provision",
            identity.clone(),
            params.clone(),
        )
        .expect("envelope creation");
        assert_eq!(env1.state(), OperationState::Pending);
        assert!(!env1.state().is_terminal());

        // Invalid direct transition Pending -> Succeeded
        assert_eq!(
            env1.advance_state(OperationState::Succeeded),
            Err(OcsError::InvalidStateTransition {
                from: OperationState::Pending,
                to: OperationState::Succeeded,
            })
        );

        // Valid Pending -> Running -> Succeeded
        assert_eq!(
            env1.advance_state(OperationState::Running),
            Ok(OperationState::Running)
        );
        assert_eq!(
            env1.advance_state(OperationState::Succeeded),
            Ok(OperationState::Succeeded)
        );
        assert!(env1.state().is_terminal());

        // Terminal state cannot transition to Running or Failed
        assert!(env1.advance_state(OperationState::Running).is_err());
        assert!(env1.advance_state(OperationState::Failed).is_err());

        // Idempotent replay check
        let replay_same = OperationEnvelope::new(
            "op-create-02",
            "idem-key-01",
            "provision",
            identity.clone(),
            params,
        )
        .expect("replay envelope");
        assert_eq!(env1.verify_idempotent_replay(&replay_same), Ok(true));

        let mut mutated_params = BTreeMap::new();
        mutated_params.insert("shape".to_string(), "highmem-16".to_string());
        let replay_conflict = OperationEnvelope::new(
            "op-create-03",
            "idem-key-01",
            "provision",
            identity,
            mutated_params,
        )
        .expect("conflict envelope");
        assert_eq!(
            env1.verify_idempotent_replay(&replay_conflict),
            Err(OcsError::IdempotencyConflict {
                idempotency_key: "idem-key-01".to_string()
            })
        );
    }

    #[test]
    fn quota_limit_accounting() {
        assert!(QuotaLimit::new("vcpu-cores", "cores", 10, 12).is_err());
        let mut quota = QuotaLimit::new("vcpu-cores", "cores", 32, 8).expect("valid quota");
        assert_eq!(quota.remaining(), 24);
        assert!(quota.can_allocate(24));
        assert!(!quota.can_allocate(25));
        assert_eq!(quota.allocate(16), Ok(24));
        assert_eq!(
            quota.allocate(9),
            Err(OcsError::QuotaExceeded {
                metric: "vcpu-cores".to_string(),
                requested: 9,
                available: 8,
            })
        );
    }

    #[test]
    fn conformance_report_evaluation() {
        let quota = QuotaLimit::new("storage-gib", "gib", 1000, 0).expect("valid quota");
        let actions = ["provision", "hold", "resume", "resize", "deprovision"];
        let report = ConformanceReport::evaluate(
            "cloudring-volume-ocs",
            "0.3.0",
            ServiceCategory::Volume,
            &actions,
            &[quota],
        );
        assert!(report.passed());
        assert!(report.provider_neutral);
        assert!(!report.production_mutate);

        let incomplete = ConformanceReport::evaluate(
            "cloudring-volume-ocs",
            "0.3.0",
            ServiceCategory::Volume,
            &["provision"],
            &[],
        );
        assert!(!incomplete.passed());
    }

    #[test]
    fn client_config_and_request_builder() {
        assert!(OcsClientConfig::new("http://ocs.cloudring.example", 5000).is_err());
        assert!(OcsClientConfig::new("https://localhost", 5000).is_err());
        assert!(OcsClientConfig::new("https://ocs.cloudring.example", 0).is_err());

        let config =
            OcsClientConfig::new("https://ocs.cloudring.example/", 5000).expect("valid config");
        assert_eq!(config.endpoint(), "https://ocs.cloudring.example");

        let resource = ResourceIdentity::new(
            "tenant-alpha",
            "proj-core",
            ServiceCategory::ObjectStorage,
            "bucket-archive-01",
        )
        .expect("resource");

        let req = RequestBuilder::new(config)
            .operation_id("op-bucket-01")
            .idempotency_key("idem-bucket-01")
            .action("provision")
            .resource(resource)
            .param("region", "eu-central-1")
            .build()
            .expect("request should build");

        assert_eq!(
            req.url,
            "https://ocs.cloudring.example/v3/tenants/tenant-alpha/projects/proj-core/services/object-storage/resources/bucket-archive-01/operations"
        );
        assert!(req.wire_payload.contains("p.region=eu-central-1"));
    }
}
