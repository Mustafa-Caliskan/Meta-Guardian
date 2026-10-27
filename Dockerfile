# Meta-Guardian runtime image.
#
# One image, two commands:
#   python -m backend.target_service   -> protected target API (port 8001)
#   python -m backend.main             -> SOC control plane + cockpit (port 8000)
#
# The edge sensor (webcam + psutil USB) is NOT containerised on purpose: a
# container cannot see the host's physical devices. See docs/DOCKER.md.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# OpenCV wheels need these shared libraries even for headless frame encoding.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libgl1 \
        libglib2.0-0 \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend
COPY scripts ./scripts
COPY docs ./docs
COPY pytest.ini README.md LICENSE ./

RUN mkdir -p data/runtime data/fixtures data/scenarios data/history_logs quarantine \
    && useradd --create-home --uid 10001 guardian \
    && chown -R guardian:guardian /app

USER guardian

EXPOSE 8000 8001

CMD ["python", "-m", "backend.main"]
