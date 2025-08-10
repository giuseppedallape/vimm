# Usa un'immagine leggera di Python
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt || true

COPY . /app

RUN mkdir -p /app/download

ENTRYPOINT ["python", "-u", "main.py"]
CMD []