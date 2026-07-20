FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY scanner/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spacy model
RUN python -m spacy download en_core_web_lg

# Copy scanner service
COPY scanner/scanner_service.py ./scanner_service.py

# Create rules directory path
RUN mkdir -p /root/.claude/nova-rules

EXPOSE 8901

CMD ["python", "scanner_service.py"]
