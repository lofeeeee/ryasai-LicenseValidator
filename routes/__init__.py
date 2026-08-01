from .license import router as license_router
from .admin import router as admin_router
from .auth_routes import router as auth_router

__all__ = ["license_router", "admin_router", "auth_router"]
