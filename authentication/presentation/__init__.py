from fastapi import APIRouter

from .auth import router as auth_router

router = APIRouter(tags=["authentication"])
router.include_router(auth_router)
