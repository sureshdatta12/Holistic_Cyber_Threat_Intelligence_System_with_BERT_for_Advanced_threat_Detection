from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from models.threat import Base
from config import DATABASE_URL
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_db():
    """Initialize the database by creating tables only if they don't exist"""
    try:
        engine = create_engine(DATABASE_URL)
        inspector = inspect(engine)
        
        # Check if tables exist
        existing_tables = inspector.get_table_names()
        if not existing_tables:
            Base.metadata.create_all(bind=engine)
            logger.info("Database tables created successfully")
        else:
            logger.info("Database tables already exist")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise

if __name__ == "__main__":
    logger.info("Initializing database...")
    init_db() 