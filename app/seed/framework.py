from app.schemas.framework import (
    Framework,
    FrameworkPillar,
    FrameworkPrinciple,
    FrameworkStage,
    ImplementationStep,
    MaturityStep,
)


def _stages(entries: list[tuple[FrameworkStage, str]]) -> list[ImplementationStep]:
    return [ImplementationStep(stage=s, action=a) for s, a in entries]


SEED_FRAMEWORK = Framework(
    name="AI-for-Cybersecurity Strategy Framework",
    version="v0.1 (draft)",
    statement=(
        "A context-sensitive framework for responsible, evidence-based adoption of agentic AI in "
        "national cybersecurity postures of developing countries. Built from controlled simulations "
        "on the CAI framework against representative resource-constrained networks."
    ),
    pillars=[
        FrameworkPillar(
            id="pillar-governance",
            name="Governance & Sovereignty",
            summary=(
                "Establish accountable governance for AI-driven cyber tooling, with explicit "
                "sovereignty controls over data, infrastructure, and external dependencies."
            ),
            iconKey="governance",
            principles=[
                FrameworkPrinciple(
                    id="p-gov-1",
                    title="Sovereign collaborator infrastructure",
                    rationale=(
                        "Detection vectors that rely on external DNS callbacks (e.g. interactsh) "
                        "route sensitive data offshore. Frameworks must mandate in-country or "
                        "sovereign alternatives."
                    ),
                    supportingFindingIds=["fnd-011"],
                ),
                FrameworkPrinciple(
                    id="p-gov-2",
                    title="HITL as a hard scope-enforcement layer",
                    rationale=(
                        "Layer-4 human-in-the-loop guardrails proved usable for CNI scope "
                        "protection. Codify as mandatory for any agentic AI operating against CNI."
                    ),
                    supportingFindingIds=["fnd-005"],
                ),
                FrameworkPrinciple(
                    id="p-gov-3",
                    title="Auditable agent traces, retained 12+ months",
                    rationale=(
                        "Every CAI action emits an OTel span. Retention policy must support "
                        "post-incident review and inter-agency information sharing."
                    ),
                    supportingFindingIds=[],
                ),
            ],
            implementationStages=_stages([
                (FrameworkStage.FOUNDATION, "Adopt agentic-AI usage policy aligned with NIS / NCS."),
                (FrameworkStage.PILOT, "Pilot HITL guardrails on a low-risk CERT workflow."),
                (FrameworkStage.INTEGRATION, "Stand up in-country collaborator + audit pipeline."),
                (FrameworkStage.OPERATION, "Continuous audit & quarterly trace review."),
                (FrameworkStage.OPTIMIZATION, "Inter-agency trace-sharing protocols."),
            ]),
        ),
        FrameworkPillar(
            id="pillar-capacity",
            name="Capacity & Skills",
            summary=(
                "Address the hybrid AI/cyber skills gap with targeted training, regional "
                "knowledge-sharing, and lower-friction scenario authoring."
            ),
            iconKey="capacity",
            principles=[
                FrameworkPrinciple(
                    id="p-cap-1",
                    title="Two-track talent pipeline",
                    rationale=(
                        "Operating CAI well demands hybrid skills present in <10% of regional CERT "
                        "staff. Frameworks must fund both upskilling and lateral hiring."
                    ),
                    supportingFindingIds=["fnd-010"],
                ),
                FrameworkPrinciple(
                    id="p-cap-2",
                    title="Regional scenario library",
                    rationale=(
                        "Scenarios authored once and shared across regional CERTs reduce duplicate "
                        "effort and embed local threat context."
                    ),
                    supportingFindingIds=["fnd-006"],
                ),
            ],
            implementationStages=_stages([
                (FrameworkStage.FOUNDATION, "Regional training-of-trainers in CAI operation."),
                (FrameworkStage.PILOT, "Three pilot CERTs author scenarios collaboratively."),
                (FrameworkStage.INTEGRATION, "Public regional scenario library."),
                (FrameworkStage.OPERATION, "Cross-border secondments."),
                (FrameworkStage.OPTIMIZATION, "Localised CVE/threat-intel fine-tuning."),
            ]),
        ),
        FrameworkPillar(
            id="pillar-technical",
            name="Technical Integration",
            summary=(
                "Adapt agentic AI to operate under bandwidth, compute, and connectivity constraints "
                "typical of resource-limited environments."
            ),
            iconKey="technical",
            principles=[
                FrameworkPrinciple(
                    id="p-tech-1",
                    title="Constraint-aware tooling parameters",
                    rationale=(
                        "Default tool parameters (e.g. nmap rates, retries) assume modern networks. "
                        "CAI deployments must ship constraint-aware presets."
                    ),
                    supportingFindingIds=["fnd-001", "fnd-008"],
                ),
                FrameworkPrinciple(
                    id="p-tech-2",
                    title="Secondary verification before high-confidence claims",
                    rationale=(
                        "Banner-based detections produced false positives in 1/3 vulnerabilities. "
                        "Framework must require a secondary verification step before reporting at "
                        "high confidence."
                    ),
                    supportingFindingIds=["fnd-002"],
                ),
                FrameworkPrinciple(
                    id="p-tech-3",
                    title="Local-model fallback path",
                    rationale=(
                        "Hosted-API dependency creates cost and sovereignty risk. Validate local "
                        "Ollama models as a fallback path for at least recon-class scenarios."
                    ),
                    supportingFindingIds=["fnd-007"],
                ),
            ],
            implementationStages=_stages([
                (FrameworkStage.FOUNDATION, "Define resource-profile presets (low / mid / modern)."),
                (FrameworkStage.PILOT, "Run identical scenario across all three profiles."),
                (FrameworkStage.INTEGRATION, "Adopt presets as CAI configuration standard."),
                (FrameworkStage.OPERATION, "Hosted+local hybrid orchestration."),
                (FrameworkStage.OPTIMIZATION, "Continuous A/B of constraint-aware presets."),
            ]),
        ),
        FrameworkPillar(
            id="pillar-ethics",
            name="Ethics & Safety",
            summary=(
                "Treat guardrails as a research subject, not an afterthought. Continuously stress-test "
                "against adversarial inputs and update layered defences."
            ),
            iconKey="ethics",
            principles=[
                FrameworkPrinciple(
                    id="p-eth-1",
                    title="Mandatory guardrail-stress runs before deployment",
                    rationale=(
                        "24/24 success rate is encouraging but volatile across model versions. Every "
                        "new model/prompt must rerun the battery."
                    ),
                    supportingFindingIds=["fnd-003"],
                ),
                FrameworkPrinciple(
                    id="p-eth-2",
                    title="Transparent provenance for every reported claim",
                    rationale=(
                        "Reviewers must trace every reported vulnerability to the exact agent step. "
                        "Provenance is the audit primitive."
                    ),
                    supportingFindingIds=[],
                ),
            ],
            implementationStages=_stages([
                (FrameworkStage.FOUNDATION, "Publish guardrail policy & test battery."),
                (FrameworkStage.PILOT, "Stress-test prior to any pilot."),
                (FrameworkStage.INTEGRATION, "Continuous integration with new model versions."),
                (FrameworkStage.OPERATION, "Red-team rotation across regional CERTs."),
                (FrameworkStage.OPTIMIZATION, "Open guardrail benchmark for the region."),
            ]),
        ),
        FrameworkPillar(
            id="pillar-sustainability",
            name="Sustainability & Cost",
            summary=(
                "Match model choice and reporting cadence to the development context. Operationalise "
                "cost as a first-class metric."
            ),
            iconKey="sustainability",
            principles=[
                FrameworkPrinciple(
                    id="p-sus-1",
                    title="Model-tiering by task class",
                    rationale=(
                        "Opus delivers no precision/recall lift over Sonnet on recon-class tasks at "
                        "7× the cost. Tier the model by task class."
                    ),
                    supportingFindingIds=["fnd-004", "fnd-009"],
                ),
                FrameworkPrinciple(
                    id="p-sus-2",
                    title="Executive-ready reporting outputs",
                    rationale=(
                        "Non-technical stakeholders require one-page summaries. Reporting layer is "
                        "the highest-leverage productivity gap."
                    ),
                    supportingFindingIds=["fnd-012"],
                ),
            ],
            implementationStages=_stages([
                (FrameworkStage.FOUNDATION, "Cost dashboards per scenario / per task class."),
                (FrameworkStage.PILOT, "Pilot model-tiering policy."),
                (FrameworkStage.INTEGRATION, "Adopt PDF + JSON reporting as standard outputs."),
                (FrameworkStage.OPERATION, "Quarterly cost review by CERT directors."),
                (FrameworkStage.OPTIMIZATION, "Continuous model-tier optimisation."),
            ]),
        ),
    ],
    maturityLadder=[
        MaturityStep(
            stage=FrameworkStage.FOUNDATION,
            label="Foundation",
            description="Policy, presets, and base training are in place. No operational deployment.",
        ),
        MaturityStep(
            stage=FrameworkStage.PILOT,
            label="Pilot",
            description="Low-risk pilots running on a single CERT, with HITL guardrails active.",
        ),
        MaturityStep(
            stage=FrameworkStage.INTEGRATION,
            label="Integration",
            description="Adopted across multiple CERT workflows; regional sharing in motion.",
        ),
        MaturityStep(
            stage=FrameworkStage.OPERATION,
            label="Operation",
            description="Standard tooling across regional CERTs; continuous audit and cost review.",
        ),
        MaturityStep(
            stage=FrameworkStage.OPTIMIZATION,
            label="Optimization",
            description=(
                "Continuous improvement, model A/B, local-context fine-tuning, mature governance."
            ),
        ),
    ],
)
