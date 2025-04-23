from fastapi import APIRouter, Depends, HTTPException, status
from app.service.authenticate_user import authenticate_user
from app.db.schemas.login import LoginRequest, TokenResponse
from app.db.schemas.logout import RefreshRequest, LogoutResponse
from sqlalchemy.future import select
from datetime import datetime, timezone,timedelta
from app.core.security import create_access_token, create_refresh_token, get_current_user
from app.db.models.refresh_token import RefreshToken
from app.db.schemas.validate import TokenValidationResponse
from app.db.models.user import User, UserRole
from app.db.schemas.curator import UserCreate, UpdateRoleRequest
from app.service.password import get_password_hash, verify_password
from app.db.database import  AsyncSession, get_db
from app.db.schemas.credentials import ChangeCredentialsRequest

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
        refresh_token=token_obj.token,
        token_type="bearer"
    )


@router.post('/validate', response_model=TokenValidationResponse)
async def validate_token(
        current_user: User = Depends(get_current_user)
) -> TokenValidationResponse:
    return TokenValidationResponse(
        is_valid=True,
        user_id=current_user.id,
        role=current_user.role
    )


@router.post(
    "/create_curator",
    status_code=status.HTTP_201_CREATED,
    summary="Создание пользователя куратора (только для председателей)"
)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.role != UserRole.CHAIRMAN_TEAM:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только председатели могут создавать пользователей"
        )
    existing_user = await db.execute(
        select(User).where(User.email == user_data.email))
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким email уже существует"
        )
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        email=user_data.email,
        hashed_password=hashed_password,
        full_name=user_data.full_name,
        role=UserRole.CURATOR.value,  # Всегда создаем куратора
        is_active=True
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return {
        "id": new_user.id,
        "email": new_user.email,
        "full_name": new_user.full_name,
        "role": new_user.role,
        "is_active": new_user.is_active
    }


@router.patch(
    "/users/{user_id}/role",
    status_code=status.HTTP_200_OK,
    summary="Изменение роли пользователя (только для председателей)"
)
async def update_user_role(
        user_id: int,
        role_data: UpdateRoleRequest,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # Проверка прав доступа
    if current_user.role != UserRole.CHAIRMAN_TEAM.value:  # Используем .value, если role хранится как enum
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Только председатели могут изменять роли пользователей"
        )

    # Проверка, что нельзя изменить свою собственную роль
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Нельзя изменить свою собственную роль"
        )

    # Поиск пользователя
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    # Проверка, что новая роль валидна
    if role_data.role not in [role.value for role in UserRole]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Недопустимая роль. Допустимые значения: {[role.value for role in UserRole]}"
        )
    # Обновление роли
    user.role = role_data.role
    await db.commit()
    await db.refresh(user)
    #пока что председ может понизить председа
    return {
        "message": "Роль пользователя успешно обновлена",
        "user_id": user.id,
        "new_role": user.role  # Убрали .value, так как role уже строка
    }


@router.post(
    "/change-credentials",
    status_code=status.HTTP_200_OK,
    summary="Смена email и/или пароля"
)
async def change_credentials(
        credentials_data: ChangeCredentialsRequest,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
):
    # Проверка текущего пароля
    if not verify_password(credentials_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный текущий пароль"
        )

    updates = {}

    # Обновление email (если предоставлен)
    if credentials_data.new_email:
        # Проверка, что email не занят другим пользователем
        existing_user = await db.execute(
            select(User).where(User.email == credentials_data.new_email))
        if existing_user.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email уже используется другим пользователем"
            )
        updates["email"] = credentials_data.new_email

    # Обновление пароля (если предоставлен)
    if credentials_data.new_password:
        if len(credentials_data.new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Пароль должен содержать минимум 8 символов"
            )
        updates["hashed_password"] = get_password_hash(credentials_data.new_password)

    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Не указаны новые данные для изменения"
        )

    # Применяем изменения
    for key, value in updates.items():
        setattr(current_user, key, value)

    await db.commit()
    await db.refresh(current_user)

    return {
        "message": "Данные успешно обновлены",
        "email_changed": credentials_data.new_email is not None,
        "password_changed": credentials_data.new_password is not None
    }