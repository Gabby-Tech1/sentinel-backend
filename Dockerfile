FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=10000

WORKDIR /app

COPY pyproject.toml ./
COPY app ./app
RUN python -m pip install --no-cache-dir .

# The lab binds privileged ports (22, 80, 443) on loopback inside the
# container. Keep the image's default root user for these simulated services.
# Only the API port is exposed publicly by Render.
EXPOSE 10000

# A single worker owns the lab, active experiment, and SSE subscribers.
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --host 0.0.0.0 --port \"${PORT:-10000}\" --workers 1"]
