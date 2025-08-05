import uvicorn
from loguru import logger

from config.base import get_settings
from core.infrastructure.logging import RequestTrackingMiddleware, setup_logging


def create_app():
    """Create and configure FastAPI application instance

    Sets up application lifespan events, middleware, exception handlers,
    and API routers.

    Returns
    -------
    FastAPI
        Deployment-ready FastAPI instance.

    Raises
    ------
    Exception
        If exception occurs in lifespan or API routers.

    """
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, HTTPException
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from pydantic import ValidationError
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from config.database import close_database_engine, create_tables, run_migrations
    from core.infrastructure.exceptions import global_exception_handler
    from core.infrastructure.factory import (
        close_redis_cache_service,
        get_redis_cache_service,
    )

    @asynccontextmanager
    async def custom_lifespan(app):
        """Manage application startup and shutdown lifecycle.

        Handles application logging setup, database and redis connection initialization,
        and proper cleanup during shutdown to prevent resource leaks.

        Parameters
        ----------
        app : FastAPI
            FastAPI application instance.

        Yields
        ------
        None
            Control to application before after startup, and before shutdown.

        Raises
        ------
        Exception
            If database table creation or migration, or Redis connection fails.
            If database or Redis shutdown fails.
        """
        setup_logging()

        try:
            logger.debug("🔧 Creating non-existent database tables...")
            await create_tables()

            logger.debug("🔧 Running unapplied database migrations...")
            await run_migrations()

        except Exception as e:
            logger.error(f"📝 Migration or table creation failed: {e}")
            raise e

        try:
            logger.debug("🔧 Initializing Redis connection...")
            redis_service = await get_redis_cache_service()
            redis_client = await redis_service._get_redis()
            ping_result = await redis_client.ping()
            logger.info(f"🟢 Redis pinged: <green>{ping_result}</green>.")

        except Exception as e:
            logger.error(f"🔴 Redis connection failed: {e}")
            raise e

        logger.info("🟢 Application startup completed.")
        logger.info("🚀✨ <green>Legendary Spoon is now running!</green>")

        yield

        logger.debug("🔧 Starting shutdown cleanup...")

        try:
            logger.debug("🔧 Closing Redis connection...")
            await close_redis_cache_service()
        except Exception as e:
            logger.error(f"🟠 Error closing Redis: {e}")

        try:
            logger.info("🔧 Closing database connections 🔧")
            await close_database_engine()
        except Exception as e:
            logger.error(f"🟠 Error closing database: {e}")

        logger.debug("👋 Application shutting down...")

    app = FastAPI(lifespan=custom_lifespan)

    app.add_middleware(RequestTrackingMiddleware)

    app.add_exception_handler(ValueError, global_exception_handler)
    app.add_exception_handler(IntegrityError, global_exception_handler)
    app.add_exception_handler(SQLAlchemyError, global_exception_handler)
    app.add_exception_handler(Exception, global_exception_handler)
    app.add_exception_handler(ValidationError, global_exception_handler)
    app.add_exception_handler(RequestValidationError, global_exception_handler)
    app.add_exception_handler(ResponseValidationError, global_exception_handler)
    app.add_exception_handler(HTTPException, global_exception_handler)
    app.add_exception_handler(StarletteHTTPException, global_exception_handler)

    try:
        from authentication.presentation import router as auth_router
        from users.presentation import router as user_router

        app.include_router(auth_router)
        app.include_router(user_router)
    except Exception as e:
        logger.error(f"🔴 Runtime error: {e}")

    return app


if __name__ == "__main__":
    """Application entry point for direct execution.

    Configures logging with Loguru and starts Uvicorn server with SSL support.
    """
    setup_logging()
    settings = get_settings()
    logger.debug(
        f"🟢 Starting Legendary Spoon in '{settings.environment.upper()}' mode!"
    )
    uvicorn.run(
        "main:create_app",
        port=8001,
        reload=settings.debug,
        factory=True,
        log_config=None,
        ssl_keyfile=settings.ssl_keyfile_path,
        ssl_certfile=settings.ssl_certfile_path,
    )
