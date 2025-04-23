from pydantic import BaseModel

class RefreshRequest(BaseModel):
    refresh_token: str

class LogoutResponse(BaseModel):
    message: str
    success: bool