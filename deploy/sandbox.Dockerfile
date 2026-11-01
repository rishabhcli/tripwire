# Sandbox image: python + pytest, nothing else. No credentials are baked in.
FROM python:3.12-slim
RUN pip install --no-cache-dir pytest==8.3.4 && useradd -u 65534 -M -s /usr/sbin/nologin sandbox 2>/dev/null || true
COPY tripwire/runtime/sitecustomize.py /opt/tripwire/sitecustomize.py
ENV PYTHONPATH=/opt/tripwire PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /work
