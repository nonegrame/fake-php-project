#!/usr/bin/env bash
set -euo pipefail
: "${GOOGLE_CLOUD_PROJECT:?Set GOOGLE_CLOUD_PROJECT to an isolated GCP project ID}"
REGION="${REGION:-asia-east1}"
SERVICE="${SERVICE:-php-mirage-honeypot}"
SA="honeypot-runtime@${GOOGLE_CLOUD_PROJECT}.iam.gserviceaccount.com"
gcloud config set project "$GOOGLE_CLOUD_PROJECT"
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com iam.googleapis.com
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 || \
  gcloud iam service-accounts create honeypot-runtime --display-name='Unprivileged honeypot runtime'
gcloud run deploy "$SERVICE" \
  --source . \
  --region "$REGION" \
  --service-account "$SA" \
  --allow-unauthenticated \
  --ingress all \
  --min-instances 0 \
  --max-instances 1 \
  --concurrency 1 \
  --memory 512Mi \
  --cpu 1 \
  --timeout 10 \
  --no-cpu-boost \
  --quiet
printf '\nView logs:\n'
printf 'gcloud run services logs read %s --region %s --limit 50\n' "$SERVICE" "$REGION"
