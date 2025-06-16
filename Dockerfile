FROM python:3.13-slim

# Set env variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Create non-root user and group
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy app files and set ownership
COPY . .
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Default command (can be overridden by docker-compose.yml)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "calorie_tracker:app"]
