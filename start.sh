#!/bin/bash

# Kill any existing uvicorn processes
pkill -f uvicorn

# Export Python path
export PYTHONPATH=/Users/anuragch/Desktop/Ad\ 4-2\ 2:$PYTHONPATH

# Create PostgreSQL database if it doesn't exist
createdb threat_intelligence 2>/dev/null || true

# Initialize the database
python database/init_db.py

# Start the server
uvicorn api.main:app --reload --port 8000 --host 0.0.0.0 