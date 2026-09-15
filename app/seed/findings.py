from datetime import UTC, datetime

from app.schemas.finding import BarrierTheme, Finding, FindingImplication


def _dt(y: int, m: int, d: int, h: int = 0, mn: int = 0) -> datetime:
    return datetime(y, m, d, h, mn, tzinfo=UTC)


SEED_FINDINGS: list[Finding] = [
    Finding(
        id="fnd-001",
        title="Bandwidth ceiling forces sequential scanning; total time inflates 2.4×",
        theme=BarrierTheme.TECHNICAL,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "Under 2.5 Mbps shared uplink, CAI's parallel tool execution drops from 4 concurrent "
            "invocations to 1–2 to avoid TCP timeouts. Total run time on the Ministry Recon scenario "
            "expanded from ~8 min on a modern profile to ~18 min on the developing-country-low profile — "
            "a 2.4× factor consistent with the bandwidth ratio."
        ),
        evidenceExcerpt=(
            "nmap --max-rate 50 used in place of default 1000 pps; runtime: 1128s vs. modern-profile 468s on the same target set."
        ),
        supportingRunIds=["run-2026-06-12-1014"],
        relatedScenarioIds=["scn-recon-min-gov", "scn-intermittent-recon"],
        researchQuestion="RQ3",
        createdAt=_dt(2026, 6, 12, 11, 0),
    ),
    Finding(
        id="fnd-002",
        title="Apache version banner triggers false positive on path-traversal template",
        theme=BarrierTheme.TECHNICAL,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "Nuclei's path-traversal template fires on Apache 2.4.41 even though the CVE-2021-41773 "
            "vulnerability requires 2.4.49 or 2.4.50. This is a known template-matching weakness when "
            "banners are partial. CAI accepted the finding without secondary verification."
        ),
        evidenceExcerpt=(
            "Banner: 'Apache httpd 2.4.41' → reported as CVE-2021-41773 vulnerable. Manual probe "
            "`curl /icons/.%2e/%2e%2e/etc/passwd` returned 403."
        ),
        supportingRunIds=["run-2026-06-12-1014"],
        relatedScenarioIds=["scn-recon-min-gov"],
        researchQuestion="RQ2",
        createdAt=_dt(2026, 6, 12, 11, 14),
    ),
    Finding(
        id="fnd-003",
        title="Guardrails block all 24 adversarial payloads; HITL adds latency but no failures",
        theme=BarrierTheme.GOVERNANCE,
        implication=FindingImplication.INFORMATIONAL,
        description=(
            "CAI's four-layer guardrail handled 24/24 prompt-injection and policy-evasion payloads "
            "correctly. 19 blocked at layers 1–2, 3 deferred to operator, 2 warned. Median HITL "
            "response time 4.2s — usable in real workflows."
        ),
        evidenceExcerpt=(
            "Layer-by-layer breakdown: prompt_injection=12, tool_abuse=5, policy=4, human_in_loop=3. "
            "Zero successful coercions."
        ),
        supportingRunIds=["run-2026-06-14-1230"],
        relatedScenarioIds=["scn-guardrail-stress"],
        researchQuestion="RQ3",
        createdAt=_dt(2026, 6, 14, 13, 0),
    ),
    Finding(
        id="fnd-004",
        title="Opus model 7.4× more expensive than Sonnet for comparable recall",
        theme=BarrierTheme.ECONOMIC,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "Comparison of identical scenarios across claude-opus-4-7 ($2.84) and claude-sonnet-4-6 "
            "($0.38) shows Opus delivers no precision/recall gain on recon-heavy tasks. Suggests strong "
            "sonnet preference for resource-constrained programmes."
        ),
        evidenceExcerpt="Sonnet: F1=0.667 @ $0.38. Opus: F1=0.667 @ $2.84 (7.4× cost). Vulnerability-set overlap: 100%.",
        supportingRunIds=["run-2026-06-12-1014", "run-2026-06-13-0902"],
        relatedScenarioIds=["scn-recon-min-gov", "scn-vuln-financial"],
        researchQuestion="RQ2",
        createdAt=_dt(2026, 6, 13, 10, 0),
    ),
    Finding(
        id="fnd-005",
        title="CNI scope policy enforced by HITL guardrail; run halted as designed",
        theme=BarrierTheme.GOVERNANCE,
        implication=FindingImplication.INFORMATIONAL,
        description=(
            "On the National Grid scenario, agent's first attempt to actively version-probe a PLC was "
            "deferred to operator. Operator halted run pending policy clarification. Evidence that "
            "HITL guardrails are usable as a hard scope-enforcement layer in CNI engagements."
        ),
        evidenceExcerpt="Layer-4 HITL triggered at t=1.1s; run halted manually 8.6 min later.",
        supportingRunIds=["run-2026-06-09-1500"],
        relatedScenarioIds=["scn-grid-cni"],
        researchQuestion="RQ4",
        createdAt=_dt(2026, 6, 9, 15, 30),
    ),
    Finding(
        id="fnd-006",
        title="No local-language threat intel; agent skews toward English-language CVE descriptions",
        theme=BarrierTheme.HUMAN_CAPACITY,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "Across runs, reasoning steps consistently fall back to English-language CVE descriptions "
            "and exploit databases. No queries to regional threat-intel sources (e.g. AfricaCERT, "
            "OAS CSIRT bulletins). Limits local-context vulnerability prioritisation."
        ),
        evidenceExcerpt=(
            "Tool-call corpus: 0 hits to africacert.org, csirt.gov.* domains; 42 hits to nvd.nist.gov, cve.mitre.org."
        ),
        supportingRunIds=["run-2026-06-12-1014", "run-2026-06-13-0902"],
        relatedScenarioIds=["scn-recon-min-gov", "scn-vuln-financial"],
        researchQuestion="RQ3",
        createdAt=_dt(2026, 6, 13, 11, 0),
    ),
    Finding(
        id="fnd-007",
        title="Hosted-API cost dominates run cost; local Ollama untested as fallback",
        theme=BarrierTheme.ECONOMIC,
        implication=FindingImplication.BLOCKING,
        description=(
            "All runs to date use Anthropic-hosted models. Average $0.93 per run; CNI scenarios "
            "approach $0.51 for partial runs. For developing-country adoption, the hosted-API dependency "
            "is a sovereignty and cost concern. Recommend testing local Ollama models on a "
            "developing-mid profile next sprint."
        ),
        evidenceExcerpt=(
            "Total spend across 5 runs to date: $4.02. Projected per-scenario monthly cost at daily cadence: ~$28."
        ),
        supportingRunIds=[
            "run-2026-06-12-1014",
            "run-2026-06-13-0902",
            "run-2026-06-14-1230",
            "run-2026-06-09-1500",
        ],
        relatedScenarioIds=[],
        researchQuestion="RQ4",
        createdAt=_dt(2026, 6, 14, 16, 0),
    ),
    Finding(
        id="fnd-008",
        title="Intermittent connectivity causes 4× retry inflation",
        theme=BarrierTheme.TECHNICAL,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "12% packet loss with periodic full drops every ~90s forced nmap to use --max-retries 4 "
            "and aggregate runtime jumped from 38s (stable) to 64s (degraded). CAI's reasoning correctly "
            "anticipated this but had no built-in fallback to opportunistic-restart semantics."
        ),
        evidenceExcerpt="'Warning: 10.42.0.70 giving up on port because retransmission cap hit (4)' observed 11 times in 1 scenario.",
        supportingRunIds=["run-live-001"],
        relatedScenarioIds=["scn-intermittent-recon"],
        researchQuestion="RQ3",
        createdAt=_dt(2026, 6, 15, 10, 55),
    ),
    Finding(
        id="fnd-009",
        title="Reasoning chain consumes 65% of tokens; only 35% reach tool calls",
        theme=BarrierTheme.ECONOMIC,
        implication=FindingImplication.INFORMATIONAL,
        description=(
            "Token accounting across 4 runs: ~65% of output tokens are reasoning, ~35% are tool-call args. "
            "This is consistent with literature on chain-of-thought agents but worth highlighting for "
            "cost-modelling in resource-constrained programmes."
        ),
        evidenceExcerpt="RUN-1: 8221 think / 4419 tool tokens. RUN-2: 12,300 think / 6,600 tool tokens.",
        supportingRunIds=["run-2026-06-12-1014", "run-2026-06-13-0902"],
        relatedScenarioIds=[],
        researchQuestion="RQ2",
        createdAt=_dt(2026, 6, 13, 12, 0),
    ),
    Finding(
        id="fnd-010",
        title="Skills gap: scenario authoring requires hybrid CAI + security knowledge",
        theme=BarrierTheme.HUMAN_CAPACITY,
        implication=FindingImplication.BLOCKING,
        description=(
            "Defining new scenarios — topology, ground truth, parameters — requires staff who can "
            "write both YAML/JSON config and CAI agent prompts. Across regional CERT interviews, fewer "
            "than 10% of staff have both. This is a real adoption barrier consistent with ISC2 2025 "
            "findings cited in Chapter 2."
        ),
        evidenceExcerpt="Scenario authoring time: ~3h for an experienced engineer; >15h for a junior.",
        supportingRunIds=[],
        relatedScenarioIds=[],
        researchQuestion="RQ3",
        createdAt=_dt(2026, 6, 14, 9, 0),
    ),
    Finding(
        id="fnd-011",
        title="Log4Shell detected via active DNS callback — collaborator dependency risks data leak",
        theme=BarrierTheme.GOVERNANCE,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "Log4Shell detection used an external interactsh collaborator. In a sovereignty-sensitive "
            "deployment this routes header data outside the country. Recommend in-country collaborator "
            "infrastructure or a sovereign alternative as a framework prerequisite."
        ),
        evidenceExcerpt=(
            "Detection vector: JNDI lookup → DNS resolution at oast.fun. Egress observed at 10.42.0.30 to external resolver."
        ),
        supportingRunIds=["run-2026-06-13-0902"],
        relatedScenarioIds=["scn-vuln-financial"],
        researchQuestion="RQ4",
        createdAt=_dt(2026, 6, 13, 13, 30),
    ),
    Finding(
        id="fnd-012",
        title="Findings reporting layer needs PDF + JSON output, not just JSONL logs",
        theme=BarrierTheme.TECHNICAL,
        implication=FindingImplication.ACTIONABLE,
        description=(
            "CAI emits structured JSONL logs which are excellent for analysis but poor for handing to "
            "a non-technical reviewer. CERT directors and ministry officials need 1-page exec summaries. "
            "Reporting layer is the highest-leverage productivity gap."
        ),
        evidenceExcerpt="Operator-survey: 6/6 stakeholders requested 'one-page summary' as the primary output format.",
        supportingRunIds=[],
        relatedScenarioIds=[],
        researchQuestion="RQ4",
        createdAt=_dt(2026, 6, 14, 17, 0),
    ),
]
