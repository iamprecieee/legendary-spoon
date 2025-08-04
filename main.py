import uvicorn
from loguru import logger

from config.base import get_settings
from core.infrastructure.logging import RequestTrackingMiddleware, setup_logging


def create_app():
    """Creates and configures the FastAPI application instance.

    This function sets up the application lifespan events (startup/shutdown),
    adds middleware, registers global exception handlers, and includes API routers.

    Returns:
        A configured FastAPI application instance.
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
        """Asynchronous context manager for managing application startup and shutdown events.

        During startup, it sets up logging, creates non-existent database tables, and runs migrations.
        During shutdown, it logs an application shutdown message.

        Args:
            app: The FastAPI application instance.

        Yields:
            None, after startup tasks are complete and before shutdown tasks begin.

        Raises:
            Exception: If database migration or table creation fails during startup.
        """
        setup_logging()

        try:
            logger.info("🔧 Creating non-existent database tables 🔧")
            await create_tables()

            logger.info("🔧 Running database migrations 🔧")
            await run_migrations()

        except Exception as e:
            logger.error(f"📝 Migration or table creation failed: {e}")
            raise e

        logger.info("🔧 Initializing Redis connection 🔧")
        redis_service = await get_redis_cache_service()
        redis_client = await redis_service._get_redis()
        ping_result = await redis_client.ping()
        logger.info(f"✅ Redis pinged: {ping_result} ✅")

        logger.info("✅ Application startup completed ✅")
        logger.info("🚀✨ Legendary Spoon is now running! ✨🚀")

        yield

        logger.info("🔧 Starting shutdown cleanup 🔧")

        try:
            logger.info("🔧 Closing Redis connection 🔧")
            await close_redis_cache_service()  # Use the factory's close method
        except Exception as e:
            logger.error(f"❌ Error closing Redis: {e}")

        try:
            logger.info("🔧 Closing database connections 🔧")
            await close_database_engine()
        except Exception as e:
            logger.error(f"❌ Error closing database: {e}")

        logger.info("👋 Application shutting down...")

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
    """Entry point for running the FastAPI application using Uvicorn.

    Configures logging and starts the Uvicorn server with specified host, port,
    reload settings, and SSL configurations.
    """
    setup_logging()
    settings = get_settings()
    logger.info(
        f"🚀✨ Starting Legendary Spoon in '{settings.environment.upper()}' mode! ✨🚀"
    )
    logger.info(f"🎨 Logging Level: {settings.logging_level.upper()} 🎨")
    logger.info("🔧 Configuring Uvicorn server with custom settings 🔧")
    uvicorn.run(
        "main:create_app",
        port=8001,
        reload=settings.debug,
        factory=True,
        log_config=None,
        ssl_keyfile=settings.ssl_keyfile_path,
        ssl_certfile=settings.ssl_certfile_path,
    )
