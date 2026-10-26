FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY test_environment/ test_environment/

WORKDIR /app/backend

# Hosted defaults: watch the sandbox folder, start monitoring on boot,
# and enable the "Simulate activity" button for visitors.
ENV MONITORED_DIRECTORY=/app/test_environment \
    AUTO_START_MONITOR=true \
    ENABLE_DEMO=true \
    APP_ENV=production \
    PORT=8000

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
