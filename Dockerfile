FROM python:3.12-slim

LABEL maintainer="xC0D3F4TH3R" \
      description="xPREDATOR-EYE - Enterprise Threat Intelligence Suite" \
      version="2.0.0"

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set tshark to not require manual approval for non-root
RUN echo "tshark tshark/install-setuid boolean true" | debconf-set-selections || true

# Create non-root user
RUN groupadd -r predator && useradd -r -g predator -m predator

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Install the package
RUN pip install --no-cache-dir -e .

# Create output directories
RUN mkdir -p /app/output/reports /app/output/quarantine && \
    chown -R predator:predator /app

USER predator

ENTRYPOINT ["python", "-m", "pcapanalyzer"]
CMD ["--help"]
