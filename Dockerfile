# --- Stage 1: Builder (Install dependencies) ---
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_HOME /main-server
WORKDIR $APP_HOME

# Copy only the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Final Image (Copy application and assets) ---
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV APP_HOME /main-server
WORKDIR $APP_HOME

# 1. Copy Python libraries (The packages/modules)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages

# 2. 🌟 NEW LINE: Copy Python executables (The 'gunicorn' binary) 🌟
COPY --from=builder /usr/local/bin/ /usr/local/bin/

# Copy the application code and static assets
COPY main.py .
COPY logger-server/ ./logger-server/

# Expose the port (FastAPI/Uvicorn/Gunicorn default)
EXPOSE 8000

# Command to run the application using Gunicorn
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--bind", "0.0.0.0:8000"]