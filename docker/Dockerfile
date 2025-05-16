# Dockerfile
FROM python:3.9-slim

# Set working directory
WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip
# Install dependencies
RUN pip install -r requirements.txt
RUN apt-get update && apt-get install -y curl

# Copy everything else (e.g. app.py, server.py, templates/, static/)
COPY . .

# Expose port if needed
EXPOSE 5000

# Run your app
CMD ["python", "app.py"]