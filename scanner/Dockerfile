FROM python:3.11-slim

# Install system dependencies, ca-certificates, and the Docker CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update && apt-get install -y --no-install-recommends \
    docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user and group for security hardening
RUN groupadd -g 10001 scannergroup && \
    useradd -u 10001 -g scannergroup -m -s /bin/bash scanneruser

WORKDIR /app

# Copy requirements and install
COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spacy model
RUN python -m spacy download en_core_web_lg

# Copy scanner modules
COPY scanner/ /app/scanner/

# Set ownership of the app directory to non-root user
RUN chown -R scanneruser:scannergroup /app

# Use the non-root user
USER scanneruser

# Expose the service
EXPOSE 8901

CMD ["python", "scanner/scanner_service.py"]

