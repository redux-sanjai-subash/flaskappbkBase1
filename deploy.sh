#!/bin/bash
set -e

IMAGE="flaskapp:3.13"
CONTAINER="flaskapp"

echo "Building Docker image..."
docker build -t "$IMAGE" .

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  echo "Stopping and removing existing container..."
  docker rm -f "$CONTAINER"
fi

echo "Starting new container..."
docker run -d \
  --name "$CONTAINER" \
  --restart unless-stopped \
  -p 127.0.0.1:8000:8000 \
  --env-file "$PWD/.env" \
  -v "$PWD/ssladmin.db:/app/ssladmin.db" \
  -v "$PWD/logs:/app/logs" \
  "$IMAGE" \
  gunicorn -w 1 -b 0.0.0.0:8000 run:app

echo "Deployment completed successfully."

