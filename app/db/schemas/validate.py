from pydantic import BaseModel

class TokenValidationResponse(BaseModel):
    is_valid: bool
    user_id: int | None
    role: str | None