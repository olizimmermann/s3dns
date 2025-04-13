FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# ENV 
ENV DOCKER=true
ENV LOCAL_DNS_SERVER_IP='0.0.0.0'
ENV REAL_DNS_SERVER_IP='1.1.1.1'
ENV BUCKET_FILE='/app/buckets/buckets.txt'

VOLUME ./bucket_file/:/app/buckets/

EXPOSE 53/udp



CMD ["python", "s3dns.py"]