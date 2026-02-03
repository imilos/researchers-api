# Use Python 3.13 slim image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libldap2-dev \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create instance directory for SQLite database with proper permissions
RUN mkdir -p /data/instance && \
    chmod 755 /data/instance

# Create a non-root user to run the application
RUN useradd -m -u 1000 fastapi-user && \
    chown -R fastapi-user:fastapi-user /app && \
    chown -R fastapi-user:fastapi-user /data

USER fastapi-user

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "app_fastapi:app", "--host", "0.0.0.0", "--port", "8000"]
