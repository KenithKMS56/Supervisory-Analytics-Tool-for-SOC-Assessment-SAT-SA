# SAT-SA Air-Gapped OCI Container
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SATSA_AIRGAPPED=1

WORKDIR /app

# Copy bundle
COPY . /app

# Install package locally
RUN pip install --no-index --find-links=wheelhouse . || pip install .

EXPOSE 8000

# Default command launches offline web UI and REST API
ENTRYPOINT ["satsa"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
