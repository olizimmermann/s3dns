# S3DNS

**s3dns** is a lightweight DNS server that helps uncover cloud storage buckets (AWS S3, Google Cloud Storage, and Azure Blob) by resolving DNS requests, tracing CNAMEs, and matching known bucket URL patterns.

It’s a handy companion for **pentesters**, **bug bounty hunters**, and **cloud security analysts** who want to catch exposed cloud buckets during DNS traffic analysis.

---

### 🆕 Update 2025/08/19

* Added offline AWS IP ranges as a JSON file.
* Added offline Azure Storage IP ranges as a JSON file.
* Added the option to disable the IP range check for either service using:
  * `AZURE_IP_RANGES=false` or `AWS_IP_RANGES=false` (default is true).
* Moved `regex_patterns` and hardcoded patterns to the `patterns` folder as YAML files. You can add your own patterns.
  * **Regex patterns must start with `regex_`.**
* Added multiple more cloud providers
  * IBM Cloud Object Storage
  * Oracle Object Storage
  * Alibaba OSS
  * Backblaze B2
  * Linode Object Storage
  * Scaleway Object Storage
  * Vultr Object Storage
  * Cloudflare R2

### 🆕 Update 2025/06/21

* Added AWS GovCloud support.

### 🆕 Update 2025/04/16

* Updated regex patterns.
* Updated output for better visibility (displaying the original domain for CNAMEs, the client IP, and IP range indicators).
* Auto-downloading of IP ranges from AWS — now checking those too!
* Option to add your own IP ranges (manually adjust the patterns or IP ranges in the class).

### 🆕 Update 2025/04/14

* Added regex support for **Google Cloud Storage** and **Azure Blob Storage** buckets.

---

## 🚀 Features

* Runs as a DNS server (port `53/udp`)
* Detects potential cloud storage buckets in DNS requests:

  * **AWS S3** (virtual-host and path style)
  * **GCP Buckets**
  * **Azure Blob Containers**
* Follows **CNAME chains** to catch masked cloud bucket links
* Logs bucket indicators to console and file
* Super lightweight and container-friendly

---

## ⚙️ How It Works

S3DNS listens on **UDP port 53** for DNS queries. For every DNS request it:

1. **Extracts the requested domain**
2. **Forwards the request to a real DNS resolver** (e.g., `1.1.1.1`)
3. **Returns the valid DNS response to the client**

In parallel, it:

* **Checks for AWS/GCP/Azure bucket patterns**
* **Checks against known IP ranges** for AWS S3 and Azure Blob Storage
* **Follows CNAME chains recursively**
* **Logs bucket-like domains and findings**

⚡ **Use this as your DNS during recon**, and it will indicate if any domains you query point to cloud buckets.

---

## 🧱 Prerequisites

* Python **3.11+**
* Docker (optional, but recommended)

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
```
```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

* If you build the image yourself, be sure to tag it the same as the Docker Hub version for consistency: `docker build -t ozimmermann/s3dns:latest .`


### Use Dockerhub

*The easiest way to get started with S3DNS.*

```bash
docker pull ozimmermann/s3dns:latest
```

When using S3DNS on the same machine where you perform analysis, it may help to set the `--network host` flag:

```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --network host \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

Since port 53 requires elevated privileges, some users (e.g., Mac users) may need `sudo`:

```bash
sudo docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --network host \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

📁 Findings are saved:

* In the **terminal**, and/or
* In `./bucket_findings/`

---

## 🌐 Using S3DNS in Recon

Set your system or tool’s **DNS resolver** to your S3DNS instance.

> While browsing or fuzzing your target, S3DNS analyzes every domain and tells you if it resolves to:
>
> * An **AWS S3 bucket**
> * A **GCP bucket**
> * An **Azure Blob container**
>
> It even **follows CNAMEs**, so if a domain points to `cdn.example.com`, which in turn points to a cloud bucket, it will catch that too.

Use it passively while analyzing a site to **spot exposed buckets without active probing**.

---

## ⚙️ Configuration

You can tweak behavior via environment variables or by modifying `s3dns.py`.

### Environment Variables

* `DEBUG`: Enable debug mode (default: `false`)
* `AWS_IP_RANGES`: Enable AWS IP range checks (default: `true`)
* `AZURE_IP_RANGES`: Enable Azure IP range checks (default: `true`)
* `REAL_DNS_SERVER_IP`: Set the real DNS server IP (default: `1.1.1.1`)
* `LOCAL_DNS_SERVER_IP`: Set the local DNS server IP / listening interface (default: `0.0.0.0`)
* `BUCKET_FILE`: Set the bucket file path (default: `buckets.txt`)

#### ⚠️ Information about Azure IP Ranges

Since Microsoft does not explicitly name their Azure Blob Storage IP ranges, S3DNS uses **all publicly provided Azure Storage IP addresses**. This may lead to false positives. Consider disabling this check if you encounter issues by setting:

```bash
AZURE_IP_RANGES=false
```

### Add own patterns
Feel free to customize your patterns by adding them to the `patterns` directory. You can create new YAML files with your desired patterns. If you need to modify existing patterns, you can do so directly in the corresponding YAML files.
Be sure to follow the naming conventions used in the existing pattern files. For regex based patterns, start with `regex_`. All other patterns will be treated as hardmatch/hardcoded patterns.

---

### Debug Mode

**Python:**

```bash
su
export DEBUG=TRUE
python s3dns.py
```

**Docker:**

```bash
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  -e "DEBUG=TRUE" \
  --name "s3dns" \
  ozimmermann/s3dns:latest
```

Setting other environment variables in Docker:

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

![Sample Output Docker](https://github.com/olizimmermann/s3dns/blob/main/images/output.jpg)

---

## 📄 License

MIT License — Free to use, improve, and share.

---

## ⚠️ Disclaimer

Use responsibly. Only scan domains you **own** or have **explicit permission** to analyze.

Unauthorized access or probing may be illegal.
