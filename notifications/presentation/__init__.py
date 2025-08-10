from fastapi import APIRouter

from .notification import router as notification_router

router = APIRouter(tags=["notifications"])
router.include_router(notification_router)
