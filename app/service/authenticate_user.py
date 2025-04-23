from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .password import verify_password
from app.db.models.user import User
from fastapi import HTTPException, status

async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str
) -> User:
    """
    Асинхронная аутентификация пользователя
    """
    # Асинхронный запрос к базе данных
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пользователь с таким email не найден",
        )

    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный пароль",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Пользователь деактивирован",
        )

    return user