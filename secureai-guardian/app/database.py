"""
SecureAI Guardian - MongoDB Database Connection
"""

from motor.motor_asyncio import AsyncIOMotorClient
from app.config import settings
import logging

logger = logging.getLogger(__name__)

class Database:
    client: AsyncIOMotorClient = None
    db = None


db = Database()


async def connect_to_mongo():
    """Create database connection."""
    try:
        db.client = AsyncIOMotorClient(settings.MONGODB_URL)
        db.db = db.client[settings.MONGODB_DB_NAME]
        # Test connection
        await db.client.admin.command("ping")
        logger.info(f"✅ Connected to MongoDB: {settings.MONGODB_DB_NAME}")

        # Create indexes
        await create_indexes()
    except Exception as e:
        logger.warning(f"⚠️  MongoDB not available, using in-memory mode: {e}")
        db.db = None


async def close_mongo_connection():
    """Close database connection."""
    if db.client:
        db.client.close()
        logger.info("MongoDB connection closed.")


async def create_indexes():
    """Create necessary indexes."""
    if db.db is None:
        return
    try:
        await db.db.logs.create_index("timestamp")
        await db.db.logs.create_index("severity")
        await db.db.threats.create_index("detected_at")
        await db.db.threats.create_index("severity")
        await db.db.users.create_index("username", unique=True)
        logger.info("✅ Database indexes created")
    except Exception as e:
        logger.error(f"Index creation error: {e}")


def get_database():
    return db.db