from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class RefreshIn(BaseModel):
    refresh_token: str = Field(min_length=40)


class UserOut(BaseModel):
    id: str
    email: str
    is_admin: bool
    created_at: int


class TokensOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'
    expires_in: int


class IssueKeyIn(BaseModel):
    owner_email: EmailStr
    expires_days: int = Field(ge=1, le=3650)
    device_limit: int = Field(default=1, ge=1, le=10)
    note: str = Field(default='', max_length=200)


class KeyOut(BaseModel):
    id: str
    prefix: str
    owner_email: str
    note: str
    created_at: int
    expires_at: int
    revoked_at: int | None
    device_limit: int
    device_count: int
    is_active: bool


class KeyIssuedOut(KeyOut):
    secret: str


class KeyActionIn(BaseModel):
    key: str = Field(min_length=30, max_length=200)
    device_id: str = Field(min_length=16, max_length=128)
    label: str = Field(default='', max_length=80)


class VerifyOut(BaseModel):
    valid: bool
    device_code: str | None = None  # Stable app identifier, not hardware UDID


class ActivationOut(BaseModel):
    id: str
    label: str
    created_at: int
    device_code: str = ''  # Human-readable alias, not the Apple UDID


class MessageOut(BaseModel):
    message: str


class CreateAPICredentialIn(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class APICredentialOut(BaseModel):
    id: str
    prefix: str
    label: str
    created_at: int
    revoked_at: int | None


class APICredentialIssuedOut(APICredentialOut):
    secret: str
