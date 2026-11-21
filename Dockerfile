FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --gid 10001 studio \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin studio

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --requirement requirements.txt
COPY *.py ./
COPY case_data/ ./case_data/
COPY migrations/ ./migrations/
COPY public/ ./public/

USER 10001:10001
CMD ["python", "-B", "server.py"]
