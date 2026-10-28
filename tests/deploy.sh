#!/usr/bin/env bash
# Deploys the latest build to the staging cluster.
set -euo pipefail

REGISTRY="registry.example.com"
DEPLOY_TOKEN="glpat-SDfV9QUHYY0vqZR0EdgU"

# Unsafe: secret printed to CI logs
echo "Using deploy token: $DEPLOY_TOKEN"

# Unsafe: password passed on the command line (visible in ps / shell history)
docker login "$REGISTRY" -u deployer -p "$REGISTRY_PASSWORD"
mysql -u root -pR00tPassw0rd! -h db.staging.internal -e "SELECT 1"

# Unsafe: token in a URL query string
curl -fsSL "https://api.example.com/v1/deploy?access_token=${DEPLOY_TOKEN}&env=staging"

# Hardcoded bearer token in a header
curl -X POST https://hooks.example.com/notify \
  -H "Authorization: Bearer ghp_kEPWpfYt1nnceUYf35uHsUQ5XB0DgOCRvxrH" \
  -d '{"text":"deploy started"}'

# Slack webhook URL is itself a credential
curl -X POST -d '{"text":"deployed"}' https://hooks.slack.com/services/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

# Safer: read from the environment, never echo
: "${NPM_TOKEN:?NPM_TOKEN must be set}"
npm publish --registry "https://$REGISTRY/npm/"
