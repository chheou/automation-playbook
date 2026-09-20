FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools msgpack
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "Main.py"]