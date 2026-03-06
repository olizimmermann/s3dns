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
EXPOSE 53/tcp

# Send a minimal DNS query for example.com and expect a response
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "\
import socket, struct; \
query = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'; \
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
s.settimeout(3); \
s.sendto(query, ('127.0.0.1', 53)); \
s.recv(512); \
s.close()" || exit 1

CMD ["python", "s3dns.py"]
