from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def get_emails():
    return {"message": "List of emails"}
