from pydantic import BaseModel

class ChangeCredentialsRequest(BaseModel):
    current_password: str
    new_email: str | None = None
    new_password: str | None = None