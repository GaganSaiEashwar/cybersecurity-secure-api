import re
from pydantic import BaseModel, ConfigDict, Field, field_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

class RegisterRequest(StrictModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("username")
    @classmethod
    def valid_username(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,30}[A-Za-z0-9]", value):
            raise ValueError("Use 3-32 letters, numbers, dots, underscores or hyphens; start/end with a letter or number.")
        return value

    @field_validator("password")
    @classmethod
    def no_nul_password(cls, value):
        if "\x00" in value:
            raise ValueError("Password contains an invalid character.")
        return value

class LoginRequest(StrictModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)

class RecordCreate(StrictModel):
    title: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=12000)

    @field_validator("title", "body")
    @classmethod
    def reject_nul(cls, value):
        if "\x00" in value:
            raise ValueError("NUL characters are not allowed.")
        return value

class UserResponse(BaseModel):
    id: int
    username: str
    role: str

class RegisterResponse(BaseModel):
    user: UserResponse

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class RecordResponse(BaseModel):
    id: int
    title: str
    body: str
    owner_id: int
