FROM python:3.12-slim

LABEL maintainer="AbuseCLI"
LABEL description="CLI tool for AbuseIPDB IP analysis"

WORKDIR /app

RUN useradd --create-home --shell /bin/bash appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY abusecli.py .

USER appuser

ENTRYPOINT ["python", "abusecli.py"]
