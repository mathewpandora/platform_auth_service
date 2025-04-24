from fastapi import APIRouter, Depends
from app.service.authenticate_user import authenticate_user
from app.db.schemas.login import LoginRequest, TokenResponse
from app.db.schemas.logout import RefreshRequest, LogoutResponse
from app.service.login import *
from app.core.security import  get_current_user
from app.db.schemas.validate import TokenValidationResponse
from app.db.schemas.curator import UserResponse
from app.db.schemas.curator import UpdateRoleRequest
from app.db.database import  get_db
from app.db.schemas.credentials import ChangeCredentialsRequest
from app.service.logout import *
from app.service.refresh_token import *
from app.service.create_user import *
from app.service.update_user_role import *
from app.service.change_credentials import *

router = APIRouter()


@router.post('/login', response_model=TokenResponse)
async def login(
        login_data: LoginRequest,
        db: AsyncSession = Depends(get_db)
) -> TokenResponse:
    """
    :param login_data: данные для входа - схема: LoginRequest
    :param db: драйвер сессии добавляется сам
    :return: отдает json со схемой TokenResponse
    """
    user = await authenticate_user(db, login_data.email, login_data.password)


    access_token = generate_access_token(user)
    refresh_token = await create_and_save_refresh_token(db, user)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post('/logout', response_model=LogoutResponse)
async def logout(
        logout_data: RefreshRequest,
        db: AsyncSession = Depends(get_db),
        current_user=Depends(get_current_user),
) -> LogoutResponse:

    token_obj = await find_active_refresh_token(
        db,
        logout_data.refresh_token,
        current_user.id
    )

    if token_obj is None:
        return LogoutResponse(
            message="Token already invalidated or not found",
            success=False
        )

    await invalidate_refresh_token(db, token_obj)

    return LogoutResponse(
        message="Logout successful",
        success=True
    )


@router.post('/refresh', response_model=TokenResponse)
async def refresh_token(
        refresh_data: RefreshRequest,
        db: AsyncSession = Depends(get_db),
        current_user=Depends(get_current_user),
) -> TokenResponse:

    token_obj, user = await validate_refresh_token(db, refresh_data.refresh_token)

    if not token_obj or not user:
        return TokenResponse(
            access_token=None,
            refresh_token=None,
            token_type="bearer"
        )

    new_access_token = generate_new_access_token(user)

    return TokenResponse(
        access_token=new_access_token,
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


@router.post("/create_user", response_model=UserResponse)
async def update_user_role_enhanced(
        user_id: int,
        role_data: UpdateRoleRequest,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
) -> dict:
    verify_chairman_permissions(current_user)
    check_self_role_change(current_user, user_id)
    validate_new_role(role_data.role)

    async with db.begin():
        try:
            user = await get_user_by_id(db, user_id)

            # Дополнительная проверка - нельзя понижать других председателей
            if user.role == UserRole.CHAIRMAN_TEAM.value and current_user.id != user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Нельзя изменять роль других председателей"
                )

            user.role = role_data.role
            await db.flush()
            await db.refresh(user)

            return format_role_update_response(user)

        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Ошибка при обновлении роли пользователя"
            ) from e


async def change_credentials_enhanced(
        credentials_data: ChangeCredentialsRequest,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user)
) -> dict:
    async with db.begin():
        try:
            # 1. Проверка текущего пароля
            verify_current_password(
                credentials_data.current_password,
                current_user.hashed_password
            )

            # 2. Подготовка обновлений
            updates = await prepare_updates(
                db,
                credentials_data.new_email,
                credentials_data.new_password
            )

            # 3. Применение изменений
            await apply_updates(db, current_user, updates)

            # 4. Формирование ответа
            return format_credentials_response(
                credentials_data.new_email,
                credentials_data.new_password
            )

        except HTTPException:
            await db.rollback()
            raise
        except Exception as e:
            await db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Ошибка при обновлении учетных данных"
            ) from e
