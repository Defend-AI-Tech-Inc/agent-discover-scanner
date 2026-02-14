FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Install osquery
RUN export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B && \
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY && \
    echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list && \
    apt-get update && \
    apt-get install -y osquery && \
    rm -rf /var/lib/apt/lists/*

# Install scanner from PyPI
RUN pip install --no-cache-dir agent-discover-scanner

# Set working directory
WORKDIR /scans

# Default command
CMD ["agent-discover-scanner", "--help"]
