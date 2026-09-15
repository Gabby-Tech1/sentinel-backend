from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db import init_db
from app.routes import (
    findings_router,
    framework_router,
    lab_router,
    meta_router,
    runs_router,
    scenarios_router,
)
from app.seed import seed_if_empty
from app.target_lab import get_lab


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    counts = seed_if_empty()
    if any(counts.values()):
        print(f"[sentinel-backend] seeded: {counts}")
    yield
    # Ensure the lab is torn down cleanly on shutdown.
    await get_lab().stop()


app = FastAPI(
    title="Sentinel Lab API",
    description=(
        "Backend for the Sentinel Lab thesis dashboard — "
        "AI-for-Cybersecurity Strategy Framework in developing countries."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["meta"])
def health() -> dict[str, str]:
    return {"status": "ok", "service": "sentinel-backend", "version": "0.1.0"}


app.include_router(scenarios_router)
app.include_router(runs_router)
app.include_router(findings_router)
app.include_router(framework_router)
app.include_router(lab_router)
app.include_router(meta_router)
