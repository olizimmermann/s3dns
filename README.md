# S3DNS

s3dns is a lightweight DNS server designed to uncover Amazon S3 buckets by resolving CNAME records and matching AWS S3 URL patterns. It’s a valuable tool for security researchers, penetration testers, and developers aiming to identify exposed S3 buckets during domain analysis.

### Features
	-	Acts as a DNS server that follows CNAME records
	-	Identifies and matches AWS S3 bucket URL patterns ￼
	-	Assists in discovering potentially exposed S3 buckets
	-	Lightweight and easy to deploy using Docker

### Prerequisites
	-	Python 3.11+
	-	Docker (optional, for containerized deployment)

## Installation

Clone the Repository

```sh
git clone https://github.com/olizimmermann/s3dns.git
cd s3dns
```

### Install Dependencies

```sh
pip install -r requirements.txt
```
## Usage

### Running with Python

```sh
python s3dns.py
```

### Running with Docker

```sh
docker build -t s3dns .
docker run --rm -p 53:53/udp -v "./bucket_findings/:/app/buckets/" --name "s3dns" s3dns
```

Replace 53 with your desired UDP port if necessary.

## Configuration

You can configure s3dns by setting environment variables or modifying the s3dns.py script directly.

![Sample Output Docker](https://github.com/olizimmermann/s3dns/blob/main/images/output.png)

## License

This project is licensed under the MIT License.

## Disclaimer

Use this tool responsibly and only on domains you own or have explicit permission to test. Unauthorized scanning or probing of domains may be illegal.
