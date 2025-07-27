import uvicorn
from loguru import logger

from config.base import get_settings
from core.infrastructure.logging import setup_logging


def create_app():
    from contextlib import asynccontextmanager

    from fastapi import FastAPI, HTTPException
    from fastapi.exceptions import RequestValidationError, ResponseValidationError
    from pydantic import ValidationError
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from config.database import create_tables, run_migrations
    from core.infrastructure.exceptions import global_exception_handler

    @asynccontextmanager
    async def custom_lifespan(app):
        """
        Application lifespan context manager.

        Sets up logging, runs migrations, creates tables, and logs startup/shutdown events.
        """

        setup_logging()

        try:
            logger.info("🔧 Creating non-existent database tables 🔧")
            create_tables()
            logger.info("🔧 Running database migrations and creating tables 🔧")
            run_migrations()
        except ImportError as e:
            logger.error(f"💥 Migration or table creation failed: {e}")
            raise e

        logger.info("✅ Application startup completed ✅")
        logger.info("🚀✨ Legendary Spoon is now running! ✨🚀")
        yield
        logger.info("👋 Application shutting down...")

    app = FastAPI(lifespan=custom_lifespan)

    # Register global exception handlers for various error types
    app.add_exception_handler(ValidationError, global_exception_handler)
    app.add_exception_handler(RequestValidationError, global_exception_handler)
    app.add_exception_handler(ResponseValidationError, global_exception_handler)
    app.add_exception_handler(IntegrityError, global_exception_handler)
    app.add_exception_handler(SQLAlchemyError, global_exception_handler)
    app.add_exception_handler(HTTPException, global_exception_handler)
    app.add_exception_handler(StarletteHTTPException, global_exception_handler)
    app.add_exception_handler(ValueError, global_exception_handler)
    app.add_exception_handler(Exception, global_exception_handler)

    try:
        from authentication.presentation import router as auth_router
        from users.presentation import router as user_router

        # Include authentication and user routers
        app.include_router(auth_router)
        app.include_router(user_router)
    except Exception as e:
        logger.error(f"💥 Runtime error: {e}")

    return app


if __name__ == "__main__":
    settings = get_settings()
    setup_logging()
    logger.info(
        f"🚀✨ Starting Legendary Spoon in '{settings.environment.upper()}' mode! ✨🚀"
    )
    logger.info(f"🎨 Logging Level: {settings.logging_level.upper()} 🎨")
    logger.info("🔧 Configuring Uvicorn server with custom settings 🔧")
    uvicorn.run(
        "main:create_app",
        factory=True,
        reload=True,
        port=8001,
        ssl_keyfile=settings.ssl_keyfile_path,
        ssl_certfile=settings.ssl_certfile_path,
        log_config=None,
    )
