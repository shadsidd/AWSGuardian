# Use official Python image
FROM python:3.9-slim-buster

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Create necessary directories
RUN mkdir -p /app/reports /app/logs /app/config

# Create non-root user
RUN useradd -m scanner && \
    chown -R scanner:scanner /app
USER scanner

# Expose port for API
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["python", "-m", "aws_security_scanner.cli"]
CMD ["run", "--config", "/app/config/config.yaml"]
