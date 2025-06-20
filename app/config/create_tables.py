from app.config.database import Base, engine
import asyncio
from app.models import demande_achat


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

if __name__ == "__main__":
    asyncio.run(create_tables())