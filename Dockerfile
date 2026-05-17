# Use official Python image
FROM python:3.11-slim

# Install system dependencies for Scapy and packet processing
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY dpi-engine-python/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY dpi-engine-python/ .

# Expose the port Hugging Face Spaces uses
EXPOSE 7860

# Command to run the application, listening on port 7860
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
