from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


# ── Register ──
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    nickname: str = Field(..., min_length=1, max_length=100)


class RegisterResponse(BaseModel):
    user_id: str
    email: str
    nickname: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Login ──
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Token Refresh ──
class RefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Logout ──
class LogoutResponse(BaseModel):
    message: str = "logged out"


# ── User Profile Update ──
class UserUpdateRequest(BaseModel):
    nickname: str = Field(..., min_length=1, max_length=100)


class UserUpdateResponse(BaseModel):
    user_id: str
    email: str
    nickname: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Password Change ──
class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class PasswordChangeResponse(BaseModel):
    message: str = "비밀번호가 변경되었습니다"


# ── Account Delete ──
class UserDeleteRequest(BaseModel):
    password: str


class UserDeleteResponse(BaseModel):
    message: str = "회원 탈퇴가 처리되었습니다"
