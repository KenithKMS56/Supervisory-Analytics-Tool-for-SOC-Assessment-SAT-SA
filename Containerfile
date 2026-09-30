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

# Default command launches offline web UI and REST API. Inside the container it listens on
# every container interface so the port can be published; publish it on the host's loopback
# unless other machines are meant to reach it:  -p 127.0.0.1:8000:8000
ENTRYPOINT ["satsa"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
