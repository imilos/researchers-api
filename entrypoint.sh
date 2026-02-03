#!/bin/bash

# Start cron daemon (as root)
cron

# Change to non-root user and start FastAPI
exec su fastapi-user -c "uvicorn app_fastapi:app --host 0.0.0.0 --port 8000"
