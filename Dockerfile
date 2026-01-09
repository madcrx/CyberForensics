FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    libpcap-dev \
    tcpdump \
    net-tools \
    iputils-ping \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make CLI executable
RUN chmod +x cli/main.py

# Create data directories
RUN mkdir -p /data/samples \
             /data/signatures \
             /data/wordlists \
             /data/evidence \
             /data/reports \
             /data/output

# Set Python path
ENV PYTHONPATH=/app:$PYTHONPATH

# Default command
CMD ["/bin/bash"]
