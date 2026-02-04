#!/bin/bash
# Build and run the ClipHub container locally

set -e

echo "======================================"
echo "Building ClipHub Docker Image"
echo "======================================"

# Build the Docker image
docker build -t cliphub:latest .

echo ""
echo "======================================"
echo "Build Complete!"
echo "======================================"
echo ""
echo "To run the container:"
echo "  docker run -d -p 9999:9999 --name cliphub cliphub:latest"
echo ""
echo "Or use docker-compose:"
echo "  docker-compose up -d"
echo ""
echo "To view logs:"
echo "  docker logs -f cliphub"
echo ""
echo "To stop:"
echo "  docker stop cliphub"
echo "  docker rm cliphub"
echo ""
