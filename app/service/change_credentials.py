from fastapi import HTTPException, status
from app.db.models.user import User
from sqlalchemy.future import select
from app.db.database import  AsyncSession
from app.service.password import get_password_hash, verify_password

def verify_current_password(
    current_password: str,
    hashed_password: str
) -> None:
    if not verify_password(current_password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный текущий пароль"
        )


async def check_email_availability(
    db: AsyncSession,
    new_email: str
) -> None:
    existing_user = await db.execute(select(User).where(User.email == new_email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email уже используется другим пользователем"
        )


def validate_new_password(new_password: str) -> None:
    if new_password and len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пароль должен содержать минимум 8 символов"
        )


async def prepare_updates(
        db: AsyncSession,
        new_email: str | None,
        new_password: str | None
) -> dict:
    updates = {}

    if new_email:
        await check_email_availability(db, new_email)
        updates["email"] = new_email

    if new_password:
        validate_new_password(new_password)
        updates["hashed_password"] = get_password_hash(new_password)

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не указаны новые данные для изменения"
        )

    return updates


async def apply_updates(
    db: AsyncSession,
    user: User,
    updates: dict
) -> None:
    for key, value in updates.items():
        setattr(user, key, value)
    await db.commit()
    await db.refresh(user)


def format_credentials_response(
    new_email: str | None,
    new_password: str | None
) -> dict:
    return {
        "message": "Данные успешно обновлены",
        "email_changed": new_email is not None,
        "password_changed": new_password is not None
    }