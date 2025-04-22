from fastapi import APIRouter

router = APIRouter()

@router.get("/ping")
async def ping():
    return {"message": "pong from auth"}


@router.post('/login')
async def login():
    pass
