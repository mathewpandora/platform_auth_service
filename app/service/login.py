from app.core.security import create_access_token, create_refresh_token
from datetime import datetime, timezone, timedelta
from app.db.models.user import User
from app.db.models.refresh_token import RefreshToken
from app.db.database import  AsyncSession


def generate_access_token(user: User) -> str:
    return create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=30)
    )

async def create_and_save_refresh_token(db: AsyncSession, user: User) -> str:
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
    return refresh_token_str