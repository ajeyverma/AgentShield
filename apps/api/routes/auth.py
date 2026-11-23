"""
AgentShield AI — Authentication Routes.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from apps.api.dependencies import CurrentUser, DbSession
from agentshield.core.exceptions import AuthenticationError
from agentshield.identity.schemas import TokenResponse, UserCreate, UserLogin, UserResponse
from agentshield.identity.service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(data: UserCreate, db: DbSession) -> UserResponse:
    """Register a new human user with Argon2 password hashing."""
    service = UserService(db)
    try:
        return await service.register(data)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/login", response_model=TokenResponse)
async def login(data: UserLogin, db: DbSession) -> TokenResponse:
    """Authenticate with username/email and password to receive a JWT access token."""
    service = UserService(db)
    try:
        return await service.authenticate(data.username_or_email, data.password)
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc.message),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(user: CurrentUser) -> UserResponse:
    """Retrieve the currently authenticated user's profile."""
    return UserResponse.model_validate(user)
