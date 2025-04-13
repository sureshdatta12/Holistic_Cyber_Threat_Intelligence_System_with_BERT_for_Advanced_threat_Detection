from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
import uvicorn
from datetime import datetime
import os
from dotenv import load_dotenv
from api.routers import threat_intelligence

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="Threat Intelligence Platform",
    description="API for analyzing and managing threat intelligence data",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://localhost:3002", "http://localhost:3003"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Total-Count"],
)

# Include routers
app.include_router(threat_intelligence.router)

# Configure logging
logger.add(
    "logs/api.log",
    rotation="500 MB",
    retention="10 days",
    level="INFO"
)

@app.get("/")
async def root():
    """Root endpoint returning API status"""
    return {
        "message": "Welcome to the Threat Intelligence Platform API",
        "docs_url": "/docs",
        "redoc_url": "/redoc"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions"""
    logger.error(f"HTTP error occurred: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle general exceptions"""
    logger.error(f"Unexpected error occurred: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"message": "Internal server error"},
    )

# Main entry point
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,
        workers=4
    ) 