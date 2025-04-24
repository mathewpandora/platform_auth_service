from app.db.database import  AsyncSession
from app.db.models.refresh_token import RefreshToken
from app.db.models.user import User
from datetime import timedelta
from sqlalchemy.future import select
from app.core.security import create_access_token


async def validate_refresh_token(
        db: AsyncSession,
        token_str: str
) -> tuple[RefreshToken | None, User | None]:
    """Возвращает (refresh_token_obj, user) или (None, None) если невалидный"""
    stmt = select(RefreshToken).where(
        RefreshToken.token == token_str,
        RefreshToken.is_active.is_(True)
    )
    result = await db.execute(stmt)
    token_obj = result.scalar_one_or_none()

    if not token_obj:
        return None, None

    user = await db.execute(select(User).filter(User.id == token_obj.user_id))
    return token_obj, user.scalar_one_or_none()


def generate_new_access_token(user: User) -> str:
    return create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=30)
    )