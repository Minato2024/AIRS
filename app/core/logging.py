import structlog
import logging
import sys
from typing import Any

# Configure standard library logging
def configure_logging():
    """Configure structured logging for AIRS"""
    
    # Set up standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.INFO,
    )
    
    # Configure structlog
    structlog.configure(
        processors=[
            # Add timestamp
            structlog.processors.TimeStamper(fmt="iso"),
            # Add log level
            structlog.processors.add_log_level,
            # Format exceptions nicely
            structlog.processors.format_exc_info,
            # Convert to JSON (for production) or console (for dev)
            structlog.dev.ConsoleRenderer()  # Use JSONRenderer() for production
        ],
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger()


def get_logger(name: str = "airs") -> Any:
    """Get a structured logger instance"""
    return structlog.get_logger(name)


# Request logging middleware for FastAPI
class RequestLoggingMiddleware:
    """Middleware to log all incoming requests"""
    
    def __init__(self, app):
        self.app = app
        self.logger = get_logger("airs.request")
    
    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request_method = scope["method"]
            request_path = scope["path"]
            
            self.logger.info(
                "Request started",
                method=request_method,
                path=request_path,
            )
        
        await self.app(scope, receive, send)