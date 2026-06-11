"""
SecureAI Guardian - Authentication API Routes
"""

from fastapi import APIRouter, HTTPException, status, Depends
from datetime import timedelta
import uuid
from datetime import datetime

from app.schemas import UserCreate, UserLogin, Token, UserResponse
from app.security import (
    verify_password, get_password_hash,
    create_access_token, get_current_user
)
from app.config import settings
from app.storage import memory_store

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """Register a new user account."""
    # Check if username already exists
    existing = memory_store.find_one("users", {"username": user.username})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    user_id = str(uuid.uuid4())
    now = datetime.utcnow()

    user_doc = {
        "_id": user_id,
        "username": user.username,
        "email": user.email,
        "hashed_password": get_password_hash(user.password),
        "role": user.role,
        "created_at": now.isoformat(),
    }

    memory_store.insert_one("users", user_doc)

    return UserResponse(
        username=user.username,
        email=user.email,
        role=user.role,
        created_at=now,
    )



@router.post("/login", response_model=Token)
async def login(credentials: UserLogin):
    """Authenticate and get JWT access token safely."""

    try:
        user = memory_store.find_one("users", {"username": credentials.username})

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # SAFE password check
        if not verify_password(credentials.password, user.get("hashed_password", "")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        access_token = create_access_token(
            data={"sub": user["username"], "role": user["role"]},
            expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "username": user["username"],
            "role": user["role"],
        }

    except HTTPException as e:
        # re-raise clean FastAPI errors
        raise e

    except Exception as e:
        # THIS prevents "Internal Server Error HTML"
        raise HTTPException(
            status_code=500,
            detail=f"Login service error: {str(e)}"
        )


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info."""
    user = memory_store.find_one("users", {"username": current_user["username"]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username": user["username"],
        "email": user.get("email", ""),
        "role": user["role"],
        "created_at": user.get("created_at"),
    }


@router.get("/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    """List all users (admin only)."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    users = memory_store.find("users", {})
    return [
        {"username": u["username"], "email": u.get("email", ""), "role": u["role"]}
        for u in users
    ]