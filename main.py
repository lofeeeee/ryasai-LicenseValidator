"""License Manager Server — multi-app license validation & management."""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from loguru import logger

from config import settings
from db import init_db
from auth import ensure_admin_exists, get_current_admin
from middleware import RateLimitMiddleware, AbuseDetectionMiddleware
from routes import license_router, admin_router
from routes.auth_routes import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("License Manager starting...")
    await init_db()
    await ensure_admin_exists()
    logger.info("Database initialized")
    yield
    logger.info("License Manager shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    description="Multi-app license validation and management server",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

# ─── Middleware ───────────────────────────────────────────────────────────────

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:8000",
    "http://localhost:9000",
]
if settings.CORS_ORIGINS:
    ALLOWED_ORIGINS.extend(settings.CORS_ORIGINS.split(","))

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)

app.add_middleware(RateLimitMiddleware)
app.add_middleware(AbuseDetectionMiddleware)

# ─── Routes ───────────────────────────────────────────────────────────────────

# Public: license validation (called by client apps)
app.include_router(license_router, prefix="/api/v1/license", tags=["License"])

# Public: auth (login + setup)
app.include_router(auth_router, prefix="/api/v1/admin/auth", tags=["Auth"])

# Protected: admin management (requires JWT)
app.include_router(
    admin_router,
    prefix="/api/v1/admin",
    tags=["Admin"],
    dependencies=[Depends(get_current_admin)],
)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "license-manager", "version": settings.APP_VERSION}


# ─── Admin Dashboard (static HTML) ────────────────────────────────────────────

DASHBOARD_DIR = Path(__file__).parent / "dashboard"


@app.get("/", include_in_schema=False)
@app.get("/dashboard", include_in_schema=False)
async def serve_dashboard():
    """Serve the admin dashboard."""
    return FileResponse(DASHBOARD_DIR / "index.html")
