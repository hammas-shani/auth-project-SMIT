from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.orm import declarative_base
from app.utils.config import settings

# Async engine
engine = create_async_engine(settings.DATABASE_URL, echo=False, future=True)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

Base = declarative_base()


# Dependency for async DB access
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
