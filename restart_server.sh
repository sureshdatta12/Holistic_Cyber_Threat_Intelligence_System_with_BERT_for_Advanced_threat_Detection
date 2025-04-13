#!/bin/bash

# Kill any existing uvicorn processes
pkill -f uvicorn

# Initialize the database
python database/init_db.py

# Start the server
uvicorn api.main:app --reload --port 8000 