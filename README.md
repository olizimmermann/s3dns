# S3DNS

**s3dns** is a lightweight DNS server that helps uncover cloud storage buckets (AWS S3, Google Cloud Storage, and Azure Blob) by resolving DNS requests, tracing CNAMEs, and matching known bucket URL patterns.

It’s a handy companion for **pentesters**, **bug bounty hunters**, and **cloud security analysts** who want to catch exposed cloud buckets during DNS traffic analysis.

---
### 🆕 Update 2025/08/20
- Added offline AWS IP ranges as a JSON file.
- Added offline Azure Storage IP ranges as a JSON file.
- Added the option to disable the IP range check for either service using:
  - AZURE_IP_RANGES=false or AWS_IP_RANGES=false (default is true).
- Moved regex_patterns and hardcoded patterns to the patterns folder as YAML files. You can add your own patterns. 
  - Regex patterns must start with regex_.

### 🆕 Update 2025/06/21

- Added AWS Gov Cloud

### 🆕 Update 2025/04/16

- Updated Regex Patterns
- Updated Output for better visibility (Displaying the original domain in case of CNAMES, the ip of the client, IP range indicator)
- Auto downloading of IP ranges from AWS - checking those too now!
- Giving you the option to add own IP ranges (First lines of the class, manually adjust the patterns or ip ranges)


### 🆕 Update 2025/04/14

- Added regex support for **Google Cloud Storage** and **Azure Blob Storage** buckets

---

## 🚀 Features

- Runs as a DNS server (port `53/udp`)
- Detects potential cloud storage buckets in DNS requests
  - **AWS S3** (virtual + path style)
  - **GCP Buckets**
  - **Azure Blob Containers**
- Follows **CNAME chains** to catch masked cloud bucket links
- Logs bucket indicators to console and file
- Super lightweight and container-friendly

---

## ⚙️ How It Works

S3DNS listens on **UDP port 53** for DNS queries. For every DNS request it:

1. **Extracts the requested domain**
2. **Forwards the request to a real DNS resolver** (e.g., `1.1.1.1`)
3. **Returns the valid DNS response to the client**
4. In parallel, it:
   - **Checks for AWS/GCP/Azure bucket patterns**
   - **Checks against known IP ranges** for AWS S3 and Azure Blob Storage
   - **Follows CNAME chains recursively**
   - **Logs bucket-like domains and findings**

⚡ **Use this as your DNS during recon**, and it’ll tell you if any domains you're touching point to cloud buckets.

---

## 🧱 Prerequisites

- Python **3.11+**
- Docker (optional, but recommended)

---

## 🔧 Installation

### Clone the Repository

```bash
git clone https://github.com/olizimmermann/s3dns.git
cd s3dns
```

### Install Dependencies

(Using a virtual environment is recommended)

```bash
pip install -r requirements.txt
```

---

## 🧪 Usage

### Run with Python

Port 53 requires elevated privileges:

```bash
sudo python s3dns.py
```

### Build and Run with Docker

```bash
docker build -t ozimmermann/s3dns:latest .
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

### ⚡️ Use Dockerhub (https://hub.docker.com/r/ozimmermann/s3dns)
*This is the easiest way to get started with S3DNS.*

```bash
docker pull ozimmermann/s3dns:latest
```

When you want to use S3DNS (in Docker) on the same machine where you perform your analysis, it can help setting the `--network host` flag. 

```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --network host \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```
Since port 53 requires that elevated privileges, some users (Mac users for example) need `sudo` here as well.

```bash
sudo docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --network host \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

📁 You'll find all findings:
- In your **terminal**
- Or in `./bucket_findings/`

---

## 🌐 Using S3DNS in Recon

Set your system or tool’s **DNS resolver to your S3DNS instance**.

> While browsing or fuzzing your target, S3DNS will analyze every domain and tell you if it resolves to:
> - An **AWS S3 bucket**
> - A **GCP bucket**
> - An **Azure blob container**
>
> It even **follows CNAMEs**, so if a domain is pointing to something like `cdn.example.com`, which in turn points to a cloud bucket—it’ll catch that too.

Use it passively while analyzing a site to **spot exposed buckets without active probing.**

---

## ⚙️ Configuration

You can tweak the behavior by setting environment variables or modifying `s3dns.py` directly.

### Possible Environment Variables

- `DEBUG`: Enable debug mode (default: `false`)
- `AWS_IP_RANGES`: Enable AWS IP range checks (default: `true`)
- `AZURE_IP_RANGES`: Enable Azure IP range checks (default: `true`)
- `REAL_DNS_SERVER_IP`: Set the real DNS server IP (default: `1.1.1.1`)
- `LOCAL_DNS_SERVER_IP`: Set the local DNS server IP / the listening interface (default: `0.0.0.0`)
- `BUCKET_FILE`: Set the bucket file path (default: `buckets.txt`)

#### ⚠️ Information about AZURE IP Ranges
Since Microsoft does not explicitly name their Azure Blob Storage IP ranges, S3DNS uses all publicly provided Azure Storage IP addresses. This may lead to false positives. Consider disabling this check if you encounter issues by setting AZURE_IP_RANGES=false.

### Debug

Enabling debug mode with **Python**:

```bash
su
export DEBUG=TRUE
python s3dns.py
```

**Docker**:

```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  -e "DEBUG=TRUE" \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

Setting other environment vars in **Docker**:

```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  -e "LOCAL_DNS_SERVER_IP=0.0.0.0" \
  -e "REAL_DNS_SERVER_IP=1.1.1.1" \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

---

## 🖼️ Sample Output

![Sample Output Docker](https://github.com/olizimmermann/s3dns/blob/main/images/output.png)

---

## 📄 License

MIT License — Free to use, improve, and share.

---

## ⚠️ Disclaimer

Use responsibly. Only scan domains you **own** or have **explicit permission** to analyze.

Unauthorized access or probing may be illegal.