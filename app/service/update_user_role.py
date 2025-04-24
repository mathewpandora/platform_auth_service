from fastapi import HTTPException, status
from app.db.models.user import User, UserRole
from sqlalchemy.future import select
from app.db.database import  AsyncSession


def verify_chairman_permissions(current_user: User) -> None:
    if current_user.role != UserRole.CHAIRMAN_TEAM.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только председатели могут изменять роли пользователей"
        )

def check_self_role_change(current_user: User, target_user_id: int) -> None:
    if current_user.id == target_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Нельзя изменить свою собственную роль"
        )

async def get_user_by_id(db: AsyncSession, user_id: int) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )
    return user


def validate_new_role(role: str) -> None:
    valid_roles = [role.value for role in UserRole]
    if role not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Недопустимая роль. Допустимые значения: {valid_roles}"
        )


def format_role_update_response(user: User) -> dict:
    return {
        "message": "Роль пользователя успешно обновлена",
        "user_id": user.id,
        "new_role": user.role
    }