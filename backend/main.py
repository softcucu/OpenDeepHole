"""FastAPI application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

import uuid

from backend.api import admin, agent, auth, checkers, feedback, integration, scan, skills
from backend.auth import hash_password
from backend.config import apply_no_proxy, get_config
from backend.logger import get_logger
from backend.registry import get_registry
from backend.store import get_scan_store

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown."""
    config = get_config()
    apply_no_proxy()

    # Ensure storage directories exist
    Path(config.storage.projects_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.scans_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.user_skills_dir).mkdir(parents=True, exist_ok=True)

    # Initialize scan store and recover from unclean shutdown
    store = get_scan_store()
    recovered = store.mark_running_as_error()
    if recovered:
        logger.warning("Marked %d interrupted scan(s) as error on startup", recovered)

    # Seed default admin user if no users exist
    if store.count_users() == 0:
        auth_cfg = config.auth
        admin_id = uuid.uuid4().hex
        agent_token = uuid.uuid4().hex
        store.create_user(
            admin_id,
            auth_cfg.default_admin_username,
            hash_password(auth_cfg.default_admin_password),
            "admin",
            agent_token,
        )
        logger.info(
            "Created default admin user '%s' (change password after first login)",
            auth_cfg.default_admin_username,
        )

    # Discover checkers on startup
    registry = get_registry()
    logger.info("Loaded %d checkers: %s", len(registry), list(registry.keys()))

    logger.info("OpenDeepHole backend started on port %d", config.server.port)
    yield
    store.close()
    logger.info("OpenDeepHole backend shutting down")


app = FastAPI(
    title="OpenDeepHole",
    description="SKILL-based C/C++ source code white-box audit tool",
    version="0.1.0",
    lifespan=lifespan,
)

# API routes
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(scan.router)
app.include_router(integration.router)
app.include_router(checkers.router)
app.include_router(skills.router)
app.include_router(feedback.router)
app.include_router(agent.router)
app.include_router(agent.public_router)

# Serve frontend static files (built by Vite)
static_dir = Path(__file__).parent / "static"
if static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
