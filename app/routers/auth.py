from fastapi import APIRouter, Depends
from app.service.authenticate_user import authenticate_user
from app.db.schemas.login import LoginRequest, TokenResponse
from app.core.security import create_access_token, create_refresh_token
from datetime import timedelta
from app.db.database import  AsyncSession, get_db

router = APIRouter()


@router.post('/login', response_model=TokenResponse)
async def login(
        login_data: LoginRequest,
        db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    user = await authenticate_user(db, login_data.email, login_data.password)

    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=30)
    ) # Сколько будет дейсвтителен аксес токен - тут !!!

    refresh_token = create_refresh_token(
        data={"sub": user.email}
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )