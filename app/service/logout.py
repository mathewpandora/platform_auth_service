from app.db.database import  AsyncSession
from app.db.models.refresh_token import RefreshToken
from sqlalchemy.future import select


async def find_active_refresh_token(
    db: AsyncSession,
    token_str: str,
    user_id: int
) -> RefreshToken | None:
    stmt = select(RefreshToken).where(
        RefreshToken.token == token_str,
        RefreshToken.user_id == user_id,
        RefreshToken.is_active.is_(True)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def invalidate_refresh_token(
    db: AsyncSession,
    token_obj: RefreshToken
) -> None:
    token_obj.is_active = False
    await db.commit()