FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories for config and logs
RUN mkdir -p /app/config /app/results

EXPOSE 5000

# Run interactive menu by default (no arguments triggers menu mode)
ENTRYPOINT ["python", "sec-tool.py"]
