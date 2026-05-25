#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/dquery/frontend"
DEPLOY_DIR="/var/www/dqueryd"
RELEASE_DIR="$DEPLOY_DIR/releases/$(date +%Y%m%d%H%M%S)"
LOCK_FILE="/tmp/dqueryd-frontend-deploy.lock"

exec 9>"$LOCK_FILE"
flock -n 9

cd "$APP_DIR"
npm ci
npm run build
/opt/deploy-hooks/bin/inject-privacy-analytics-token.mjs "$APP_DIR/dist/privacy-plugins.json"

install -d "$RELEASE_DIR"
cp -a "$APP_DIR/dist/." "$RELEASE_DIR/"
ln -sfn "$RELEASE_DIR" "$DEPLOY_DIR/current"
