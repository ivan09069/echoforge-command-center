# CI_POLICY.md — EchoForge Command Center

## One-Line Rule

No change merges without 748+ tests passing. No incident closes without a replay fixture.

---

## 1. Required Test Suite

Every merge must pass the full suite. No exceptions. No overrides.

| File | Tests | Layer | Blocking |
|---|---|---|---|
| `test_policy_invariants.py` | 49 | Core invariants (5 non-negotiable rules) | **YES** |
| `test_end_to_end_pipeline.py` | 58 | Full pipeline flow | **YES** |
| `test_routing_golden_corpus.py` | 289 | Classifier regression gate | **YES** |
| `test_adapter_failure_modes.py` | 49 | Adapter fault tolerance | **YES** |
| `test_mutation_resistance.py` | 65 | Guard removal detection | **YES** |
| `test_schema_boundary_validation.py` | 86 | Type enforcement at boundaries | **YES** |
| `test_live_boundary_enforcement.py` | 48 | Runtime gate verification | **YES** |
| `test_replay_fixtures.py` | 104 | Real-world payload shapes | **YES** |

**Minimum pass count**: 748 (current). This number only goes up, never down. If a test is removed, a replacement must be added in the same PR.

**Run command**:
```bash
python -m pytest tests/ -q --tb=short
```

**CI timeout**: 30 seconds. Current suite runs in ~2.5s. If it exceeds 10s, investigate before it hits 30.

---

## 2. Merge-Blocking Conditions

A merge is **blocked** if any of the following are true:

### Hard blocks (automated)
- Any test failure
- Test count below 748
- New production code without corresponding test
- `contracts.py` modified without explicit review approval
- `policy_engine.py` HARD_DEFAULTS modified without explicit review approval

### Soft blocks (require justification)
- New adapter added without replay fixtures
- New action class added without golden corpus entries
- New secret pattern added without detection + redaction tests
- Schema validation limits changed without boundary enforcement tests

### Never merge
- Code that bypasses `boundary_enforcer.py`
- Code that calls `decide()` without prior `enforce_post_adapter_*` check
- Code that sends raw adapter output to the operator without `enforce_response_policy`
- Code that routes HIGH sensitivity to CLAUDE
- Code that removes or weakens a HARD_DEFAULT

---

## 3. Incident-to-Fixture Rule

**Every production incident gets a replay fixture before the fix is considered complete.**

### Process
1. **Capture**: Save the raw adapter payload that caused the incident (sanitize secrets)
2. **Classify**: Tag with source (claude/gemini/mcp/triage), date, and failure class
3. **Add fixture**: Add to `tests/replay_fixtures.py` under the appropriate `*_MALFORMED` dict
4. **Write test**: Add a test in `test_replay_fixtures.py` that reproduces the failure
5. **Verify fail**: Confirm the test fails WITHOUT the fix applied
6. **Apply fix**: Fix the production code
7. **Verify pass**: Confirm all 748+ tests pass WITH the fix
8. **Merge**: PR must include both the fixture and the fix

### Fixture tagging convention
```python
# In replay_fixtures.py
CLAUDE_MALFORMED = {
    # ...existing...
    "incident_2026_03_22_confidence_overflow": {
        "raw": "...",
        "confidence": 999.0,
        "_incident": "INC-042",
        "_date": "2026-03-22",
        "_class": "schema_violation",
    },
}
```

### Incident classes
- `schema_violation` — payload failed schema validation
- `secret_leak` — secret appeared in output or audit
- `route_violation` — HIGH sensitivity reached cloud lane
- `gate_bypass` — execution occurred without approval
- `veto_failure` — security REJECT did not block
- `parser_drift` — verdict parsed incorrectly
- `timeout_cascade` — adapter timeout caused unexpected state
- `audit_gap` — action occurred without audit entry

---

## 4. Prod / Staging Policy Differences

### Shared (all environments)
- `contracts.py` — frozen, identical everywhere
- `schema_validation.py` — same limits everywhere
- `boundary_enforcer.py` — same enforcement everywhere
- Full test suite must pass before deploy to any environment

### Staging-specific
```python
STAGING_OVERRIDES = {
    "allow_debug_logging": True,          # Verbose adapter logs
    "allow_dry_run_execution": True,      # Simulated trades can auto-approve
    "audit_retention_days": 7,            # Short retention
    "max_raw_response_bytes": 1_000_000,  # Relaxed for debugging
}
```

### Prod-specific (strictest)
```python
PROD_OVERRIDES = {
    "allow_debug_logging": False,         # No verbose logs
    "allow_dry_run_execution": False,     # Even simulations need explicit approval
    "audit_retention_days": 90,           # Full retention
    "max_raw_response_bytes": 500_000,    # Hard cap
    "circuit_breaker_threshold": 5,       # 5 consecutive adapter failures → halt
    "escalation_storm_threshold": 10,     # 10 ESCALATEs in 5 min → alert
    "schema_failure_threshold": 3,        # 3 schema failures in 5 min → halt adapter
}
```

### Prod hard rules (non-negotiable, cannot be overridden)
```python
# These are HARD_DEFAULTS — same in all environments, not configurable
security_veto = True
default_security_mode = "read_only"
default_execution_mode = "disabled"
secrets_to_cloud = False
value_moving_requires_approval = True
high_sensitivity_requires_local = True
```

---

## 5. No-Bypass Rule for Boundary Enforcement

### The rule
There is no code path from adapter output to `decide()` that does not pass through `boundary_enforcer.py`. There is no code path from `decide()` to operator response that does not pass through `enforce_response_policy()`.

### Enforcement
- `web_ui.py` must call enforcement functions at every step
- No `decide(contract, trading, security)` call without prior:
  - `enforce_pre_route(contract)` → valid
  - `enforce_post_adapter_trading(output, contract)` → valid
  - `enforce_post_adapter_security(output, contract)` → valid
- No response sent to WebSocket without prior:
  - `enforce_response_policy(response, decision)`
  - `enforce_pre_response(decision)` → valid

### How to verify
```bash
# Must find zero instances of decide() without prior enforce_*
grep -n "decide(" web_ui.py | head -20
grep -n "enforce_pre_route\|enforce_post_adapter" web_ui.py | head -20
```

Every `decide()` call must be preceded by enforcement calls in the same code block. If a new code path is added that calls `decide()` without enforcement, the mutation resistance tests should catch it — but code review must also verify.

### Prohibited patterns
```python
# NEVER: calling decide() with unvalidated output
decision = decide(contract, raw_trading_output, raw_security_output)

# ALWAYS: validate first, use fallback if invalid
r1 = enforce_post_adapter_trading(trading_output, contract)
if not r1.valid:
    decision = r1.fallback_decision
else:
    r2 = enforce_post_adapter_security(security_output, contract)
    if not r2.valid:
        decision = r2.fallback_decision
    else:
        decision = decide(contract, r1.value, r2.value)
```

---

## 6. Frozen Files

These files require explicit review approval for any modification:

| File | Reason | Approval required |
|---|---|---|
| `contracts.py` | All schemas flow from this. Drift breaks everything. | Owner review |
| `policy_engine.py` HARD_DEFAULTS | Non-negotiable safety defaults | Owner review |
| `schema_validation.py` limits | Boundary caps protect against overflow | Owner review |
| `tests/replay_fixtures.py` valid fixtures | Removing valid fixtures weakens coverage | Owner review |
| `tests/test_policy_invariants.py` | Core safety proofs | Owner review |
| `tests/test_routing_golden_corpus.py` | Classifier regression gate | Owner review |

---

## 7. Adding New Features

Before adding any new feature:

1. **Does it touch a trust boundary?** If yes, add boundary enforcement tests first.
2. **Does it add a new action class?** If yes, add golden corpus entries + approval gate tests.
3. **Does it add a new adapter?** If yes, add replay fixtures (valid + malformed) + enforcement tests.
4. **Does it modify routing logic?** If yes, run the full golden corpus and verify no regressions.
5. **Does it touch secrets handling?** If yes, add detection + redaction + audit-clean tests.

Feature PRs must include:
- Production code
- Tests that fail without the feature
- Tests that pass with the feature
- Updated replay fixtures if a new adapter shape is introduced
- Updated ARCHITECTURE.md if the operating model changes

---

## 8. Test Ownership

| Test file | Owner concern | When to update |
|---|---|---|
| `test_policy_invariants.py` | Safety rules haven't changed | Never (unless adding new invariants) |
| `test_end_to_end_pipeline.py` | Full flow still works | When pipeline logic changes |
| `test_routing_golden_corpus.py` | Classifier semantics stable | When adding phrases or action classes |
| `test_adapter_failure_modes.py` | Failures degrade safely | When adding adapters or failure modes |
| `test_mutation_resistance.py` | Guards can't be silently removed | When adding new safety guards |
| `test_schema_boundary_validation.py` | Types enforced at boundaries | When changing schemas or limits |
| `test_live_boundary_enforcement.py` | Runtime gates active | When changing enforcement flow |
| `test_replay_fixtures.py` | Real payloads handled correctly | After every production incident |

---

## 9. Metrics to Track

| Metric | Target | Alert threshold |
|---|---|---|
| Test count | ≥748, monotonically increasing | Any decrease |
| Test runtime | <5s | >10s |
| Schema validation failures/hour (prod) | 0 | >3 in 5 minutes |
| Adapter timeouts/hour (prod) | <5 | >10 |
| ESCALATE decisions/hour (prod) | <10 | >20 |
| SECRET_LEAK detections (prod) | 0 | Any |
| Approval overrides/day (prod) | <20 | >50 |
| Audit log gaps (prod) | 0 | Any |

---

## Summary

```
Tests pass        → merge allowed
Tests fail        → merge blocked
Incident happens  → fixture added before fix closes
Prod deploys      → strictest policy, no debug bypasses
Boundary enforcer → no bypass path, ever
Frozen files      → owner review required
New features      → tests first, code second
```
