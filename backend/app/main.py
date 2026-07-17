import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.db.session import init_db
from app.api import upload, investigations

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan events to manage app startup and shutdown."""
    # Startup actions
    logger.info("Starting up FastAPI application...")
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
    yield
    # Shutdown actions
    logger.info("Shutting down FastAPI application...")

app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    version="1.0.0"
)

# CORS Middleware (Crucial for React connection)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify actual frontend domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routes
app.include_router(upload.router, prefix=f"{settings.API_V1_STR}/upload", tags=["Upload"])
app.include_router(investigations.router, prefix=f"{settings.API_V1_STR}/investigations", tags=["Investigations"])

from fastapi.responses import HTMLResponse
import os

@app.get("/dashboard", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the interactive SOC analyst dashboard."""
    templates_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(templates_dir, "templates", "dashboard.html")
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/")
async def root():
    """Welcome route."""
    return {
        "status": "online",
        "project": settings.PROJECT_NAME,
        "api_docs": "/docs",
        "dashboard": "/dashboard"
    }
