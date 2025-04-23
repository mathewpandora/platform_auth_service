from fastapi import APIRouter, Depends
from app.service.authenticate_user import authenticate_user
from app.db.schemas.login import LoginRequest, TokenResponse
from app.db.schemas.logout import RefreshRequest, LogoutResponse
from sqlalchemy.future import select
from datetime import datetime, timezone,timedelta
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.db.models.refresh_token import RefreshToken
from app.db.models.user import User

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
    )
    refresh_token_str = create_refresh_token(data={"sub": user.email})
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    refresh_token_obj = RefreshToken(
        user_id=user.id,
        token=refresh_token_str,
        expires_at=expires_at,
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    db.add(refresh_token_obj)
    await db.commit()
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )


@router.post('/logout', response_model=LogoutResponse)
async def logout(
        logout_data: RefreshRequest,
        db: AsyncSession = Depends(get_db),
        current_user = Depends(get_current_user),  # возвращает ORM-объект User
) -> LogoutResponse:
    stmt = select(RefreshToken).where(
        RefreshToken.token == logout_data.refresh_token,
        RefreshToken.user_id == current_user.id,
        RefreshToken.is_active.is_(True)
    )
    result = await db.execute(stmt)
    token_obj = result.scalar_one_or_none()

    if token_obj is None:
        return LogoutResponse(message="Token already invalidated or not found", success=False)
    token_obj.is_active = False
    await db.commit()
    return LogoutResponse(message="Logout successful", success=True)



@router.post('/refresh', response_model=TokenResponse)
async def refresh_token(
        refresh_data: RefreshRequest,
        db: AsyncSession = Depends(get_db),
        current_user=Depends(get_current_user),
) -> TokenResponse:
    stmt = select(RefreshToken).where(
        RefreshToken.token == refresh_data.refresh_token,
        RefreshToken.is_active.is_(True)
    )
    result = await db.execute(stmt)
    token_obj = result.scalar_one_or_none()
    if token_obj is None:
        return TokenResponse(access_token=None, refresh_token=None, token_type="bearer")
    user = await db.execute(select(User).filter(User.id == token_obj.user_id))
    user = user.scalar_one_or_none()

    if not user:
        return TokenResponse(access_token=None, refresh_token=None, token_type="bearer")
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=30)
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=token_obj.token,  # сохраняем тот же refresh_token
        token_type="bearer"
    )
