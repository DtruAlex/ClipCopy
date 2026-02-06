FROM python:3.11-slim

# Force logs to show up immediately
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all files (including ClipProtocol.py and ClipHub.py)
COPY . .

# Expose the port for documentation
EXPOSE 9999

# Run the script
CMD ["python", "ClipHub.py", "0.0.0.0", "9999"]