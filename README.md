# S3DNS

s3dns is a lightweight DNS server designed to uncover Amazon S3 buckets by resolving CNAME records and matching AWS S3 URL patterns. It’s a valuable tool for security researchers, penetration testers, and developers aiming to identify exposed S3 buckets during domain analysis.

### Features
- Acts as a DNS server that follows CNAME records (sometimes websites hide s3 location behind CNAMES)
- Identifies and matches AWS S3 bucket URL patterns
- Assists in discovering potentially exposed S3 buckets
- Lightweight and easy to deploy using Docker

### Prerequisites
- Python 3.11+
- Docker (optional, for containerized deployment)

## Installation

Clone the Repository

```sh
git clone https://github.com/olizimmermann/s3dns.git
cd s3dns
```

### Install Dependencies

Consider using a virtual environment.
```sh
pip install -r requirements.txt
```
## Usage

### Running with Python

Since you need to listeno on port 53, you need to run it as root.
```sh
sudo python s3dns.py
```

### Running with Docker

```sh
docker build -t s3dns .
docker run --rm -p 53:53/udp -v "./bucket_findings/:/app/buckets/" --name "s3dns" s3dns
```
You will find all findings in your console or within in the mounted folder "./bucket_finding/"

## Using S3DNS
While you exploring your target, use your S3DNS instance as your DNS server. It will forward all DNS requests to your desired DNS server (default 1.1.1.1). As soon you request a domain which contains any sign of an AWS S3 bucket, it will let you know. The smart part of S3DNS is, it will also check each domain for CNAMES and follows them, as long no other CNAME entry is left. If you found a bucket, scan it like you usually would do or get a hinch of the naming of the bucket. Maybe you find more!

## Configuration

You can configure s3dns by setting environment variables or modifying the s3dns.py script directly.

![Sample Output Docker](https://github.com/olizimmermann/s3dns/blob/main/images/output.png)

## License

This project is licensed under the MIT License.

## Disclaimer

Use this tool responsibly and only on domains you own or have explicit permission to test. Unauthorized scanning or probing of domains may be illegal.
