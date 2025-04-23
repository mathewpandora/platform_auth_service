from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.db.database import Base, engine
from app.routers import auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    # При запуске приложения — создаём таблицы
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # При остановке приложения — закрываем движок
    await engine.dispose()


app = FastAPI(lifespan=lifespan)

# Подключаем роуты
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
