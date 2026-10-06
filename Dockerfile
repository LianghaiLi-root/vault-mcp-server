FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# On Linux we always use PBKDF2 (no DPAPI). The master password comes from the
# environment / secret, never from the image.
ENV VAULT_DIR=/data/vault \
    VAULT_FORCE_PBKDF2=1 \
    VAULT_CONFIG=/app/config.yaml

VOLUME /data
EXPOSE 8080

CMD ["python", "server.py"]
