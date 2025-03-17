from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import emails
from app.core.config import settings
from app.db.session import engine, Base

# Create tables if they don’t exist (only for development, use Alembic for production)
Base.metadata.create_all(bind=engine)

# Initialize FastAPI app
app = FastAPI(title=settings.PROJECT_NAME, version=settings.VERSION)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update this to specific domains if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(emails.router, prefix="/emails", tags=["Emails"])

@app.get("/")
def root():
    return {"message": "Welcome to FastAPI Server"}

# Run using: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
