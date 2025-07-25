from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from loguru import logger
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from authentication.presentation import router as auth_router
from config.database import create_tables, run_migrations
from core.infrastructure.exceptions import global_exception_handler
from core.infrastructure.logging.base import setup_logging
from users.presentation import router as user_router


@asynccontextmanager
async def custom_lifespan(app):
    """
    Application lifespan context manager.
    Sets up logging, runs migrations (or creates tables if migrations fail),
    and logs startup/shutdown events.
    """

    setup_logging()

    try:
        run_migrations()
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        create_tables()

    logger.info("Application startup completed")
    yield
    logger.info("Application shutting down...")


app = FastAPI(lifespan=custom_lifespan)

# Register global exception handlers for various error types
app.add_exception_handler(RequestValidationError, global_exception_handler)
app.add_exception_handler(ResponseValidationError, global_exception_handler)
app.add_exception_handler(ValidationError, global_exception_handler)
app.add_exception_handler(IntegrityError, global_exception_handler)
app.add_exception_handler(SQLAlchemyError, global_exception_handler)
app.add_exception_handler(ValueError, global_exception_handler)
app.add_exception_handler(StarletteHTTPException, global_exception_handler)
app.add_exception_handler(HTTPException, global_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)

# Include authentication and user routers
app.include_router(auth_router)
app.include_router(user_router)

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True, port=8001, log_config=None)
