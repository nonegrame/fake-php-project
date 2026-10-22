# PHP Mirage — Cloud Run honeypot

A **simulation**, not a real PHP runtime. Designed to observe general PHP/WordPress probes; no shell execution, outbound callbacks, real secrets, or vulnerable PHP binaries.

## Local

```bash
docker build -t php-mirage .
docker run --rm -p 8080:8080 php-mirage
curl -i localhost:8080/phpinfo.php
curl -i 'localhost:8080/diagnostic.php?cmd=whoami'
```

## GCP Cloud Run

Use a **dedicated, isolated GCP project** with billing budget alerts. Requires gcloud login, billing enabled, and permission to deploy/create service accounts.

```bash
export GOOGLE_CLOUD_PROJECT=your-dedicated-project-id
export REGION=asia-east1
./deploy.sh
```

Cloud Run deploys directly from source/Dockerfile using Cloud Build and Artifact Registry. Build and storage can incur charges even at zero requests. The service is intentionally public. The script creates a new unprivileged runtime service account (do **not** attach roles or grant it access to other resources). If your organization enforces public access restrictions, deployment may fail; do not weaken organization controls to get around them.

```bash
gcloud run services logs read php-mirage-honeypot --region asia-east1 --limit 100
gcloud run services delete php-mirage-honeypot --region asia-east1
```

### What is simulated

- `/`: WordPress-like homepage
- `/wp-login.php`: decoy login form; **credentials are never recorded**
- `/phpinfo.php`: fake PHP information
- `/diagnostic.php?cmd=id`: static, allowlisted shell-like output; never execute input
- `/xmlrpc.php`: simulated endpoint
- `/.env`, `/.git/config`, `/wp-config.php`: fake forbidden responses

### Limitations and cautions

- It's not an actual vulnerable PHP environment, and will not faithfully reproduce PHP exploit payload behavior.
- Cloud Run terminates HTTP at Google's front end, so you **cannot reliably spoof** the public `Server` header or observe all low-level malformed/oversized traffic.
- Structured application logs deliberately exclude request bodies, passwords, cookies, authorization and raw query strings. Cloud Run platform request logs can still contain full URLs/query strings. Review Cloud Logging settings and retention; avoid sending real credentials to this service.
- No body buffering prevents surprises from huge request bodies. Cloud Run front-end enforces its own request limits.
- A maximum instance cap does not guarantee a fixed billing cap. Use billing budgets/alerts, monitor charges, and tear down after the experiment.
- If public IP attribution matters, trust platform-produced request metadata; do not blindly trust spoofable X-Forwarded-For supplied by clients.
