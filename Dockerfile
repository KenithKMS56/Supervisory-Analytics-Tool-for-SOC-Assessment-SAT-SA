FROM python:3.11-slim

# Prevent Python from writing bytecode and enable unbuffered terminal logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Inside the container the portals must listen on every container interface, or Docker's
# port publishing cannot reach them. Which HOST address they are published on is decided
# where the ports are published: docker-compose.yml publishes on 127.0.0.1 unless
# SATSA_BIND_ADDRESS says otherwise. With plain `docker run`, publish explicitly on loopback:
#   docker run -p 127.0.0.1:8000:8000 -p 127.0.0.1:8001:8001 satsa-platform
ENV SATSA_HOST=0.0.0.0

WORKDIR /app

# Install minimal OS runtime packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy build manifest and package source
COPY pyproject.toml README.md /app/
COPY src/ /app/src/

# Install SAT-SA application and all runtime dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . "websockets>=12.0"

# Copy configuration and entrypoint scripts
COPY config/ /app/config/
COPY entrypoint.py /app/entrypoint.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Ensure persistent storage mount points exist
RUN mkdir -p /app/data /app/reports

# Expose NCIIPC Administration Portal (:8000) and SAT-SA Portal (:8001)
EXPOSE 8000 8001

# Declare persistent data volumes
VOLUME ["/app/data", "/app/reports"]

# Healthcheck to verify both portals are responsive
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=5 \
    CMD python /app/entrypoint.py --healthcheck || exit 1

ENTRYPOINT ["python", "/app/entrypoint.py"]
