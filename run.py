import uvicorn
from api.main import app
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    # Get configuration from environment
    host = os.getenv("API_HOST", "0.0.0.0")
    port = int(os.getenv("API_PORT", 8000))
    debug = os.getenv("DEBUG_MODE", "True").lower() == "true"
    
    # Run the application
    uvicorn.run(
        "api.main:app",
        host=host,
        port=port,
        reload=debug,
        workers=4 if not debug else 1
    ) 