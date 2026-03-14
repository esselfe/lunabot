#!/usr/bin/env bash
#
# Lunabot Integration Test Runner
#
# Sends HMAC-signed GitHub webhook payloads to lunabot running in Docker
# and asserts the expected IRC messages appear in the observer's output.
#
# Prerequisites: Docker (with compose plugin), openssl, curl
#
# Usage: bash test/run-tests.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
WEBHOOK_URL="http://localhost:3000"
WEBHOOK_SECRET="test-webhook-secret"
PAYLOAD_DIR="$SCRIPT_DIR/payloads"
PASS_COUNT=0
FAIL_COUNT=0
OBSERVER_LOG=$(mktemp)
OBSERVER_PID=""

# Cleanup on exit
cleanup() {
    echo ""
    echo "=== Teardown ==="
    [ -n "$OBSERVER_PID" ] && kill "$OBSERVER_PID" 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
    rm -f "$OBSERVER_LOG"
    echo ""
    echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="
    if [ "$FAIL_COUNT" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}
trap cleanup EXIT

# Compute HMAC-SHA256 signature for a payload file
compute_signature() {
    local payload_file="$1"
    local hex
    hex=$(openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" "$payload_file" | sed 's/^.*= //')
    echo "sha256=$hex"
}

# Send a webhook payload, return HTTP status code
send_webhook() {
    local payload_file="$1"
    local sig
    sig=$(compute_signature "$payload_file")
    curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -H "X-Hub-Signature-256: $sig" \
        -d @"$payload_file"
}

# Assert that a substring appears in the observer log within 5 seconds
assert_output() {
    local description="$1"
    local expected="$2"
    local waited=0

    while [ "$waited" -lt 10 ]; do
        if grep -qF "$expected" "$OBSERVER_LOG" 2>/dev/null; then
            echo "  PASS: $description"
            PASS_COUNT=$((PASS_COUNT + 1))
            return 0
        fi
        sleep 0.5
        waited=$((waited + 1))
    done

    echo "  FAIL: $description (expected: '$expected')"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return 0
}

# Start capturing observer logs in the background
capture_observer_output() {
    docker compose -f "$COMPOSE_FILE" logs --follow --no-log-prefix observer > "$OBSERVER_LOG" 2>&1 &
    OBSERVER_PID=$!
}

echo "=== Lunabot Integration Tests ==="
echo ""

# Step 1: Generate TLS certificates for Ergo
echo "Generating TLS certificates..."
bash "$SCRIPT_DIR/ergo/generate-certs.sh"

# Step 2: Build and start containers
echo "Building and starting containers..."
docker compose -f "$COMPOSE_FILE" up --build -d

# Step 3: Start capturing observer logs
capture_observer_output

# Step 4: Wait for lunabot to connect and join the channel
echo "Waiting for lunabot to connect to IRC..."
WAIT_COUNT=0
while [ "$WAIT_COUNT" -lt 60 ]; do
    if docker compose -f "$COMPOSE_FILE" logs lunabot 2>/dev/null | grep -q "JOIN"; then
        echo "Lunabot connected and joined channel."
        break
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ "$WAIT_COUNT" -ge 60 ]; then
    echo "ERROR: Lunabot did not connect within 60 seconds."
    echo "Lunabot logs:"
    docker compose -f "$COMPOSE_FILE" logs lunabot 2>/dev/null || true
    exit 1
fi

# Give a moment for the observer to also join
sleep 2

echo ""
echo "=== Running Tests ==="
echo ""

# Test 1: PR opened
send_webhook "$PAYLOAD_DIR/pr_opened.json"
assert_output "PR opened" "[New PR]"
sleep 1

# Test 2: PR closed (merged)
send_webhook "$PAYLOAD_DIR/pr_closed_merged.json"
assert_output "PR closed merged" "[Merged PR]"
sleep 1

# Test 3: PR closed (not merged)
send_webhook "$PAYLOAD_DIR/pr_closed_not_merged.json"
assert_output "PR closed not merged" "[Closed PR]"
sleep 1

# Test 4: PR labeled
send_webhook "$PAYLOAD_DIR/pr_labeled.json"
assert_output "PR labeled" "added the 'enhancement' label"
sleep 1

# Test 5: PR unlabeled
send_webhook "$PAYLOAD_DIR/pr_unlabeled.json"
assert_output "PR unlabeled" "removed the 'enhancement' label"
sleep 1

# Test 6: CI status success
send_webhook "$PAYLOAD_DIR/status_success.json"
assert_output "Status success" "[Success]"
sleep 1

# Test 7: CI status pending
send_webhook "$PAYLOAD_DIR/status_pending.json"
assert_output "Status pending" "[Pending]"
sleep 1

# Test 8: CI status failure
send_webhook "$PAYLOAD_DIR/status_failure.json"
assert_output "Status failure" "[Failed]"
sleep 1

# Test 9: Push commits
send_webhook "$PAYLOAD_DIR/push_commits.json"
assert_output "Push commit" "[Commits]"
sleep 1

# Test 10: Check run lint success (should NOT produce a message, just verify no error)
HTTP_STATUS=$(send_webhook "$PAYLOAD_DIR/checkrun_lint_success.json")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "  PASS: Check run lint success (HTTP $HTTP_STATUS, no IRC message expected)"
    PASS_COUNT=$((PASS_COUNT + 1))
else
    echo "  FAIL: Check run lint success (HTTP $HTTP_STATUS, expected 200)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
fi

echo ""
