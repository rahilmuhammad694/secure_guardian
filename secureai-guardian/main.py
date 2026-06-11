"""
SecureAI Guardian - AI-Powered Security Automation Platform
Main FastAPI Application
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn
import os

from app.api.routes import auth, logs, threats, agents, dashboard
from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection

app = FastAPI(
    title="SecureAI Guardian",
    description="AI-Powered Security Automation Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Event handlers
@app.on_event("startup")
async def startup_event():
    await connect_to_mongo()
    print("✅ SecureAI Guardian started successfully")

@app.on_event("shutdown")
async def shutdown_event():
    await close_mongo_connection()

# Include API routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(logs.router, prefix="/api/logs", tags=["Security Logs"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threat Detection"])
app.include_router(agents.router, prefix="/api/agents", tags=["AI Agents"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])

# Serve static dashboard
BASE_DIR = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "frontend")), name="static")

@app.get("/", include_in_schema=False)
async def serve_dashboard():
    frontend_file = os.path.join(BASE_DIR, "frontend", "index.html")
    if os.path.exists(frontend_file):
        return FileResponse(frontend_file)
    return {"message": "SecureAI Guardian API", "docs": "/api/docs"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "SecureAI Guardian", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)