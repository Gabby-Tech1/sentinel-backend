from sqlmodel import Session, select

from app.db import models as m
from app.db.engine import engine
from app.seed.findings import SEED_FINDINGS
from app.seed.framework import SEED_FRAMEWORK
from app.seed.runs import SEED_RUNS
from app.seed.scenarios import SEED_SCENARIOS


def seed_if_empty() -> dict[str, int]:
    """Populate the DB from seed data if the tables are empty. Idempotent."""
    counts = {"scenarios": 0, "runs": 0, "findings": 0, "framework": 0}
    with Session(engine) as session:
        if not session.exec(select(m.ScenarioRow)).first():
            for scn in SEED_SCENARIOS:
                session.add(
                    m.ScenarioRow(
                        id=scn.id,
                        slug=scn.slug,
                        name=scn.name,
                        researchQuestion=scn.researchQuestion,
                        payload=scn.model_dump(mode="json"),
                    )
                )
                counts["scenarios"] += 1

        if not session.exec(select(m.RunRow)).first():
            for run in SEED_RUNS:
                session.add(
                    m.RunRow(
                        id=run.id,
                        scenarioId=run.scenarioId,
                        scenarioName=run.scenarioName,
                        status=run.status.value,
                        startedAt=run.startedAt,
                        endedAt=run.endedAt,
                        payload=run.model_dump(mode="json"),
                    )
                )
                counts["runs"] += 1

        if not session.exec(select(m.FindingRow)).first():
            for f in SEED_FINDINGS:
                session.add(
                    m.FindingRow(
                        id=f.id,
                        theme=f.theme.value,
                        researchQuestion=f.researchQuestion,
                        createdAt=f.createdAt,
                        payload=f.model_dump(mode="json"),
                    )
                )
                counts["findings"] += 1

        if not session.exec(select(m.FrameworkRow)).first():
            session.add(
                m.FrameworkRow(
                    name=SEED_FRAMEWORK.name,
                    version=SEED_FRAMEWORK.version,
                    payload=SEED_FRAMEWORK.model_dump(mode="json"),
                )
            )
            counts["framework"] = 1

        session.commit()
    return counts
