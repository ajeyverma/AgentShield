"""
AgentShield AI — Users Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.identity.schemas import UserResponse, UserUpdate
from agentshield.identity.service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
async def get_my_profile(user: CurrentUser) -> UserResponse:
    """Get the authenticated user's profile."""
    return UserResponse.model_validate(user)


@router.patch("/me", response_model=UserResponse)
async def update_my_profile(
    data: UserUpdate,
    user: CurrentUser,
    db: DbSession,
) -> UserResponse:
    """Update profile fields for the authenticated user."""
    service = UserService(db)
    try:
        return await service.update(user.id, data)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
