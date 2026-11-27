# main.py — FastAPI application entry point.

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

from .config import settings
from .routers import honeypot, dashboard
from .services.storage import storage


@asynccontextmanager
async def lifespan(app: FastAPI):
#  Startup / shutdown lifecycle manager.
    print(f"[{settings.app_name}] Starting up...")
    await storage.connect()
    print(f"[{settings.app_name}] Honeypot listening on: POST {settings.honeypot_path}")
    if settings.dashboard_enabled:
        print(f"[{settings.app_name}] Dashboard available at: {settings.dashboard_path}")
    yield
    print(f"[{settings.app_name}] Shutting down...")
    await storage.disconnect()


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/api/docs" if settings.debug else None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(honeypot.router)

if settings.dashboard_enabled:
    app.include_router(dashboard.router)

    # Serve the single-page dashboard
    @app.get(settings.dashboard_path, response_class=HTMLResponse, include_in_schema=False)
    @app.get(f"{settings.dashboard_path}/{{path:path}}", response_class=HTMLResponse, include_in_schema=False)
    async def serve_dashboard():
        dashboard_html_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
        with open(dashboard_html_path, encoding="utf-8") as f:
            return HTMLResponse(content=f.read())


@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "app": settings.app_name, "version": settings.app_version}
