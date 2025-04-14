# S3DNS

**s3dns** is a lightweight DNS server that helps uncover cloud storage buckets (AWS S3, Google Cloud Storage, and Azure Blob) by resolving DNS requests, tracing CNAMEs, and matching known bucket URL patterns.

It’s a handy companion for **pentesters**, **bug bounty hunters**, and **cloud security analysts** who want to catch exposed cloud buckets during DNS traffic analysis.

---

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

### Run with Docker

```bash
docker build -t s3dns .
docker run --rm -p 53:53/udp \
  -v "./bucket_findings/:/app/buckets/" \
  --name "s3dns" \
  s3dns
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
