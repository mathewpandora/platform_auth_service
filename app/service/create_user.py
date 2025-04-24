from fastapi import HTTPException, status
from app.db.models.user import User, UserRole
from sqlalchemy.future import select
from app.db.database import  AsyncSession
from app.service.password import get_password_hash
from app.db.schemas.curator import UserCreate

def format_user_response(user: User) -> dict:
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active
    }

def verify_chairman_permissions(current_user: User) -> None:
    if current_user.role != UserRole.CHAIRMAN_TEAM:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только председатели могут создавать пользователей"
        )

async def check_user_existence(db: AsyncSession, email: str) -> None:
    existing_user = await db.execute(select(User).where(User.email == email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )

def create_user_object(user_data: UserCreate) -> User:
    return User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.CURATOR.value,
        is_active=True
    )