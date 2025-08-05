#!/bin/bash

# Change to /src (not needed if you set WORKDIR)
cd /src/api

# Start FastAPI in the background
python -m uvicorn api:app --host 0.0.0.0 --port 8000 --reload &

# Wait a few seconds to make sure FastAPI is up
sleep 5

cd /src

# Start your second script
python deepnet_guard.py

python flask_app.py
