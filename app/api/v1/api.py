from fastapi import APIRouter
from app.api.v1.endpoints import honeypot, detection, response, dashboard

api_router = APIRouter()

api_router.include_router(honeypot.router, prefix="/honeypot", tags=["honeypot"])
api_router.include_router(detection.router, prefix="/detection", tags=["detection"])
api_router.include_router(response.router, prefix="/response", tags=["response"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])