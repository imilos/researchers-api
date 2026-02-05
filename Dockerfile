# Use Python 3.13 slim image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cron \
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

# Create instance directory for SQLite database
RUN mkdir -p /data/instance && \
    chmod 755 /data/instance

# Setup cron job - specify user in the crontab file
RUN echo "45 2 * * * fastapi-user cd /app && /usr/local/bin/python3 fetch_authorities_cli.py >> /var/log/cron.log 2>&1" > /etc/cron.d/fetch-authorities && \
    chmod 0644 /etc/cron.d/fetch-authorities

# Create and set permissions for cron log
RUN touch /var/log/cron.log && \
    chmod 666 /var/log/cron.log

# Create non-root user
RUN useradd -m -u 1000 fastapi-user && \
    chown -R fastapi-user:fastapi-user /app && \
    chown -R fastapi-user:fastapi-user /data

# Copy and make entrypoint executable
RUN chmod +x /app/entrypoint.sh /app/fetch_authorities_cli.py

EXPOSE 8000

# Run entrypoint as root
ENTRYPOINT ["/app/entrypoint.sh"]
