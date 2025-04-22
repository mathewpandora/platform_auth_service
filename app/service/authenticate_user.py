from .password import verify_password
from app.db.models.user import User
from app.db.database import AsyncSessionLocal
from fastapi import HTTPException, status

async def authenticate_user(
        db: AsyncSessionLocal,
        email: str,
        password: str
) -> User:

    # Ищем пользователя в базе данных
    user = db.query(User).filter(User.email == email).first()

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