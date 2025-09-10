# Contributing to S3DNS

Thank you for considering contributing to **S3DNS** 🚀  
Contributions are welcome — from small bug fixes and docs improvements to new features or regex patterns for additional storage services.

---

## Code of Conduct
Please be respectful and constructive. By participating in this project, you agree to uphold a welcoming and inclusive environment.

---

## How to contribute
There are several ways you can help:

- 🐛 **Report bugs**: Open an issue at `https://github.com/olizimmermann/s3dns/issues` with a clear description, steps to reproduce, and your environment (OS, Python version, Docker version).  
- ✨ **Suggest features**: Propose new detection patterns, providers, or UX improvements. Open an issue to discuss the idea before implementing larger changes.  
- 📝 **Improve docs**: Fix typos, clarify examples, or add usage guides to the README.  
- 💻 **Submit code**: Add new detection logic, improve regexes, optimize performance, add tests, or refactor code.

---

## Development setup

### Requirements
- Python **3.11+**
- Docker (recommended for testing / deployment)

### Local (Python)
1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/s3dns.git
   cd s3dns
   ```
2. Create and activate a virtual environment:
   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   ```
3. Install dependencies (if `requirements.txt` exists):
   ```bash
   pip install -r requirements.txt
   ```
4. Run locally (port 53 requires privileges):
   ```bash
   sudo python s3dns.py
   ```

### Docker
Build and run:
```bash
docker build -t s3dns .
docker run --rm -p 53:53/udp   -v "$(pwd)/bucket_findings/:/app/buckets/"   s3dns
```

For testing with local tooling, `--network host` is often helpful:
```bash
docker run --rm --network host   -v "$(pwd)/bucket_findings/:/app/buckets/"   s3dns
```

---

## Guidelines

### Branch naming
Use descriptive names:
- `fix/bug-description`
- `feat/new-feature`
- `docs/readme-update`

### Commit messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
fix(dns): handle empty CNAME responses
feat(regex): add Alibaba OSS detection
docs: clarify Docker usage
```

### Pull request checklist
Please complete this checklist before requesting review:

- [ ] I opened an issue describing the change (unless it’s a tiny fix).
- [ ] My branch is based on the latest `main`.
- [ ] The project builds and runs on Python 3.11+.
- [ ] Docker image builds successfully (if relevant).
- [ ] I added or updated tests, or provided manual test instructions.
- [ ] I updated documentation/README when user-facing behavior changed.
- [ ] I kept the PR focused and small where possible.
- [ ] I did not commit secrets or credentials.

Include in the PR description:
- A short summary of the change.
- Link to the related issue (use `Closes #<issue>` to auto-close).
- Clear steps to reproduce and test the change locally.


---

## Testing
There is no formal test suite by default. Suggested steps for contributors:

- Manually run `s3dns.py` (or Docker) and exercise domains that should match the patterns.
- Confirm findings are logged to the console and written to `./bucket_findings/`.

(Contributions that add a reproducible test harness are highly appreciated.)

---

## Security / Vulnerabilities
If you find a security vulnerability or sensitive issue, do **not** open a public issue. Instead:
- Prefer GitHub Security Advisories (if enabled), or
- Contact the maintainer via the email on the GitHub profile or a private channel listed in the repository.

When reporting, include:
- A clear description of the vulnerability and impact.
- Steps to reproduce and PoC (if available).
- Suggested mitigation or patch.

---

## Licensing
By contributing, you agree to license your contributions under this repository's license (MIT). Please check `LICENSE` for the authoritative terms.

---

## Helpful tips
- Keep PRs small and focused — easier to review and merge.
- If you plan a large refactor, open an issue first and discuss a design proposal.
- If adding new environment variables, document their names, description, and defaults in the README.

---

## Thanks 🙏
Thanks for improving **S3DNS** — your contributions make the project more useful for everyone in the security community.

