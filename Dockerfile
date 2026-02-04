# Multi-stage build for smaller final image
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Final stage
FROM python:3.11-alpine

# Security: Create non-root user
RUN addgroup -g 1000 cliphub && \
    adduser -D -u 1000 -G cliphub cliphub

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy only necessary files
COPY --chown=cliphub:cliphub ClipHub.py ClipProtocol.py ./

# Switch to non-root user
USER cliphub

# Expose port
EXPOSE 9999

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import socket; s=socket.socket(); s.settimeout(3); s.connect(('127.0.0.1', 9999)); s.close()" || exit 1

# Run the hub
CMD ["python", "-u", "ClipHub.py"]
