#!/usr/bin/env bash
set -Eeuo pipefail

RULE_URL="${RULE_URL:-https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Classical.yaml}"
APP_DIR="${APP_DIR:-/opt/dquery}"
SRC_DIR="${SRC_DIR:-/opt/dquery/rules-src}"
OUT_FILE="${OUT_FILE:-/var/lib/dqueryd/chinamax_classical.compact.json}"
LOCK_FILE="${LOCK_FILE:-/tmp/dquery-rules-update.lock}"
PUSH_TO_GITHUB="${PUSH_TO_GITHUB:-1}"
GIT_AUTHOR_NAME="${GIT_AUTHOR_NAME:-dquery-rules-bot}"
GIT_AUTHOR_EMAIL="${GIT_AUTHOR_EMAIL:-dquery-rules-bot@users.noreply.github.com}"

exec 9>"$LOCK_FILE"
flock -n 9

install -d "$SRC_DIR" "$(dirname "$OUT_FILE")"

src_tmp="$(mktemp)"
out_tmp="$(mktemp)"
cleanup() {
  rm -f "$src_tmp" "$out_tmp"
}
trap cleanup EXIT

curl -fsSL --retry 3 --retry-delay 5 "$RULE_URL" -o "$src_tmp"

"$APP_DIR/bin/chinamax-build" \
  -src "$src_tmp" \
  -include "$APP_DIR/data/local-include.txt" \
  -exclude "$APP_DIR/data/local-exclude.txt" \
  -out "$out_tmp"

install -m 0644 "$src_tmp" "$SRC_DIR/ChinaMax_Classical.yaml"
install -m 0644 "$out_tmp" "$OUT_FILE"

if command -v systemctl >/dev/null 2>&1; then
  systemctl restart dqueryd
fi

if [ "$PUSH_TO_GITHUB" = "1" ] && command -v git >/dev/null 2>&1; then
  cd "$APP_DIR"

  if ! git diff --quiet -- rules-src/ChinaMax_Classical.yaml; then
    git add rules-src/ChinaMax_Classical.yaml
    git \
      -c user.name="$GIT_AUTHOR_NAME" \
      -c user.email="$GIT_AUTHOR_EMAIL" \
      commit -m "Update ChinaMax rules $(date -u +%Y-%m-%d)"
    git push
  fi
fi
