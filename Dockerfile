FROM python:3.13-slim

WORKDIR /app

# Environment for reliable runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps often needed by common Python packages (adjust if not needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libpq-dev \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN python -m pip install --upgrade pip && pip install -r requirements.txt

# Copy app source
COPY . .

# Expose internal port
EXPOSE 8000

# Start Gunicorn; change "run:app" to "app:app" if your app object is there.
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8000", "run:app"]
