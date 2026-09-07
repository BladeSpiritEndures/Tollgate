#!/usr/bin/env bash
set -euo pipefail

: "${AWS_ACCESS_KEY_ID:=fake}"
: "${AWS_SECRET_ACCESS_KEY:=fake}"
: "${AWS_DEFAULT_REGION:=ap-southeast-2}"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION

endpoint="${DYNAMODB_ENDPOINT_URL:-http://localhost:8000}"

if aws dynamodb describe-table \
  --endpoint-url "$endpoint" \
  --table-name tollgate-keys >/dev/null 2>&1; then
  echo "tollgate-keys already exists"
  exit 0
fi

aws dynamodb create-table \
  --endpoint-url "$endpoint" \
  --table-name tollgate-keys \
  --attribute-definitions AttributeName=key_hash,AttributeType=S \
  --key-schema AttributeName=key_hash,KeyType=HASH \
  --billing-mode PROVISIONED \
  --provisioned-throughput ReadCapacityUnits=5,WriteCapacityUnits=5
