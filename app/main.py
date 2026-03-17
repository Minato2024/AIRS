from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from contextlib import asynccontextmanager
import structlog
import sys

from app.config import settings
from app.api.v1.api import api_router
from app.models.database import init_db, close_db
from app.services.detection_engine import DetectionEngine
from app.services.response_orchestrator import ResponseOrchestrator
from app.core.logging import configure_logging

# Configure structured logging
logger = configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan events.
    Handles startup and shutdown logic.
    """
    # ========== STARTUP ==========
    logger.info(
        "Starting AIRS Backend",
        version=settings.VERSION,
        environment="development" if settings.DEBUG else "production"
    )
    
    # Initialize database
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error("Database initialization failed", error=str(e))
        raise
    
    # Initialize core services
    try:
        app.state.detection_engine = DetectionEngine()
        app.state.response_orchestrator = ResponseOrchestrator()
        
        # Inject into honeypot router
        from app.api.v1.endpoints import honeypot
        honeypot.set_services(
            app.state.detection_engine,
            app.state.response_orchestrator
        )

        # Load ML models
        await app.state.detection_engine.load_models()
        
        logger.info("Core services initialized successfully")
    except Exception as e:
        logger.error("Service initialization failed", error=str(e))
        # Continue without ML models (fallback to signature detection)
    
    logger.info("AIRS Backend is operational")
    
    yield  # Application runs here
    
    # ========== SHUTDOWN ==========
    logger.info("Shutting down AIRS Backend")
    
    # Cleanup services
    if hasattr(app.state, 'detection_engine'):
        await app.state.detection_engine.cleanup()
    
    # Close database connections
    await close_db()
    
    logger.info("AIRS Backend shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="""
    Adaptive Intrusion Response System (AIRS) API.
    
    ## Features
    
    * **Honeypot Data Ingestion** - Receive and process honeypot logs
    * **Threat Detection** - Hybrid ML/Signature-based detection
    * **Automated Response** - Intelligent countermeasure selection
    * **Real-time Dashboard** - Live threat monitoring via WebSocket
    
    ## Authentication
    
    API uses JWT tokens for authentication (implement in production).
    """,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,  # Disable docs in production
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None
)

# ========== MIDDLEWARE ==========

# CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else ["http://localhost:3000", "https://yourdomain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression for responses
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ========== ROUTES ==========

# Health check (before API router)
@app.get("/")
async def root():
    """Root endpoint - API information"""
    return {
        "name": settings.APP_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "documentation": "/docs" if settings.DEBUG else None
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    health_status = {
        "status": "healthy",
        "timestamp": __import__('datetime').datetime.utcnow().isoformat(),
        "version": settings.VERSION,
        "services": {}
    }
    
    # Check detection engine
    if hasattr(app.state, 'detection_engine') and app.state.detection_engine.initialized:
        health_status["services"]["detection_engine"] = "ok"
    else:
        health_status["services"]["detection_engine"] = "degraded"
        health_status["status"] = "degraded"
    
    # Check response orchestrator
    if hasattr(app.state, 'response_orchestrator'):
        health_status["services"]["response_orchestrator"] = "ok"
    else:
        health_status["services"]["response_orchestrator"] = "error"
        health_status["status"] = "degraded"
    
    return health_status


# Include API v1 routes
app.include_router(api_router, prefix="/api/v1")


# ========== WEBSOCKET ENDPOINTS ==========

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    WebSocket endpoint for real-time threat alerts.
    Clients connect here to receive live threat notifications.
    """
    from app.api.v1.endpoints.dashboard import manager
    
    await manager.connect(websocket)
    
    try:
        while True:
            # Receive message from client
            data = await websocket.receive_text()
            
            # Handle different message types
            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": __import__('datetime').datetime.utcnow().isoformat()
                })
            elif data.startswith("subscribe:"):
                channel = data.split(":", 1)[1]
                await websocket.send_json({
                    "type": "subscribed",
                    "channel": channel
                })
            else:
                # Echo unknown messages
                await websocket.send_json({
                    "type": "echo",
                    "received": data
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Alert WebSocket disconnected")
    except Exception as e:
        logger.error("WebSocket error", error=str(e))
        manager.disconnect(websocket)


# ========== ERROR HANDLERS ==========

@app.exception_handler(__import__('fastapi').exceptions.RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle validation errors"""
    logger.warning(
        "Request validation failed",
        errors=exc.errors(),
        path=request.url.path
    )
    return __import__('fastapi').responses.JSONResponse(
        status_code=422,
        content={
            "detail": "Validation error",
            "errors": exc.errors()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle all unhandled exceptions"""
    logger.error(
        "Unhandled exception",
        error=str(exc),
        path=request.url.path,
        exc_info=True
    )
    return __import__('fastapi').responses.JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": str(exc) if settings.DEBUG else "An error occurred"
        }
    )


# ========== STARTUP (for direct execution) ==========

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info" if settings.DEBUG else "warning",
        access_log=settings.DEBUG
    )