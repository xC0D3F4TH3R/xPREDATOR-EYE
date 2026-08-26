FROM python:3.12-slim

LABEL maintainer="xC0D3F4TH3R"
LABEL description="xPREDATOR-EYE - Enterprise Threat Intelligence Suite"
LABEL version="2.0.0"

# Install system dependencies (tshark for live capture)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tshark \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set tshark to not require manual approval
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "tshark tshark/install-setuid boolean true" | debconf-set-selections

# Create app user (non-root)
RUN groupadd -r predator && useradd -r -g predator -m predator

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .
RUN pip install --no-cache-dir -e .

# Create output directories
RUN mkdir -p /app/output/reports /app/output/quarantine && \
    chown -R predator:predator /app

USER predator

ENTRYPOINT ["python", "-m", "pcapanalyzer"]
CMD ["--help"]
