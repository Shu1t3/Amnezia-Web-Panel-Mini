# syntax=docker/dockerfile:1

# Stage 1: Build dependencies
FROM python:3.14-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production image
FROM python:3.14-slim
WORKDIR /app

# Install openssh-client for SSH connections to VPN servers
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-client && \
    rm -rf /var/lib/apt/lists/*

# Create data directory for SQLite database
RUN mkdir -p /data

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

EXPOSE 8000

CMD ["python3", "app.py"]
