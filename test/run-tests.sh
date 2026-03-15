#!/usr/bin/env bash
#
# Lunabot Integration Test Runner
#
# Sends HMAC-signed GitHub webhook payloads to lunabot running in Docker
# and asserts the expected IRC messages appear in the observer's output.
#
# Prerequisites: Docker (with compose plugin), openssl, curl
#
# Usage: bash test/run-tests.sh [-v|--verbose]
#
set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        *) echo "Unknown argument: $arg" >&2; exit 1 ;;
    esac
done

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
    [[ -n "$OBSERVER_PID" ]] && kill "$OBSERVER_PID" 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
    rm -f "$OBSERVER_LOG"
    echo ""
    echo "=== Results: $PASS_COUNT passed, $FAIL_COUNT failed ==="
    if [[ "$FAIL_COUNT" -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
    return 0
}
trap cleanup EXIT

# Compute HMAC-SHA256 signature for a payload file
compute_signature() {
    local payload_file="$1"
    local hex
    hex=$(openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" "$payload_file" | sed 's/^.*= //')
    echo "sha256=$hex"
    return 0
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
        --data-binary @"$payload_file"
    return 0
}

# Assert that a substring appears in the observer log within 5 seconds
assert_output() {
    local description="$1"
    local expected="$2"
    local waited=0

    while [[ "$waited" -lt 10 ]]; do
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

# Assert that a substring does NOT appear in the observer log (wait 3 seconds to be sure)
assert_not_output() {
    local description="$1"
    local unexpected="$2"

    sleep 3
    if grep -qF "$unexpected" "$OBSERVER_LOG" 2>/dev/null; then
        echo "  FAIL: $description (unexpected: '$unexpected' was found)"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    else
        echo "  PASS: $description"
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
    return 0
}

# Start capturing observer logs in the background
capture_observer_output() {
    docker compose -f "$COMPOSE_FILE" logs --follow --no-log-prefix observer > "$OBSERVER_LOG" 2>&1 &
    OBSERVER_PID=$!
    return 0
}

# In verbose mode, dump the observer log (IRC output) to the console
dump_observer_log() {
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo ""
        echo "=== IRC output (observer log) ==="
        # Strip mIRC color codes (\x03 + up to 2 digits) for readability
        perl -pe 's/\x03(\d{1,2}(,\d{1,2})?)?//g' < "$OBSERVER_LOG" 2>/dev/null || true
        echo "=== end IRC output ==="
    fi
    return 0
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

# Step 4: Wait for lunabot's webhook endpoint to be ready and IRC connected
echo "Waiting for lunabot to start..."
WAIT_COUNT=0
while [[ "$WAIT_COUNT" -lt 60 ]]; do
    # Check if the webhook port is responding (any HTTP response means MHD is up)
    if curl -s -o /dev/null -w "%{http_code}" "$WEBHOOK_URL" 2>/dev/null | grep -qE '^[0-9]+$'; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$WEBHOOK_URL" 2>/dev/null)
        if [[ "$HTTP_CODE" != "000" ]]; then
            echo "Lunabot webhook endpoint is up (HTTP $HTTP_CODE)."
            break
        fi
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [[ "$WAIT_COUNT" -ge 60 ]]; then
    echo "ERROR: Lunabot webhook endpoint did not start within 60 seconds." >&2
    echo "Lunabot logs:"
    docker compose -f "$COMPOSE_FILE" logs lunabot 2>/dev/null || true
    exit 1
fi

# Wait for lunabot to connect to IRC and the observer to join
# The webhook is up, but IRC connection happens in a thread; give it time
echo "Waiting for IRC connections to establish..."
sleep 5

echo ""
echo "=== Running Tests ==="
echo ""

# Note: IRC messages contain mIRC color codes (\x03NN) between brackets
# and text, e.g. "[\x0303New PR\x03]". Assertions use substrings that
# don't span color code boundaries.

# Helper: send webhook and check HTTP status
send_and_check() {
    local payload_file="$1"
    local http_status
    http_status=$(send_webhook "$payload_file")
    if [[ "$http_status" != "200" ]]; then
        echo "  WARNING: Webhook returned HTTP $http_status for $(basename "$payload_file")"
    fi
    return 0
}

# Test 1: PR opened
send_and_check "$PAYLOAD_DIR/pr_opened.json"
assert_output "PR opened" "New PR"
sleep 1

# Test 2: PR closed (merged)
send_and_check "$PAYLOAD_DIR/pr_closed_merged.json"
assert_output "PR closed merged" "Merged PR"
sleep 1

# Test 3: PR closed (not merged)
send_and_check "$PAYLOAD_DIR/pr_closed_not_merged.json"
assert_output "PR closed not merged" "Closed PR"
sleep 1

# Test 4: PR labeled
send_and_check "$PAYLOAD_DIR/pr_labeled.json"
assert_output "PR labeled" "added the 'enhancement' label"
sleep 1

# Test 5: PR unlabeled
send_and_check "$PAYLOAD_DIR/pr_unlabeled.json"
assert_output "PR unlabeled" "removed the 'enhancement' label"
sleep 1

# Test 6: CI status success
send_and_check "$PAYLOAD_DIR/status_success.json"
assert_output "Status success" "Success"
sleep 1

# Test 7: CI status pending
send_and_check "$PAYLOAD_DIR/status_pending.json"
assert_output "Status pending" "Pending"
sleep 1

# Test 8: CI status failure
send_and_check "$PAYLOAD_DIR/status_failure.json"
assert_output "Status failure" "Failed"
sleep 1

# Test 9: Push commits
send_and_check "$PAYLOAD_DIR/push_commits.json"
assert_output "Push commit" "Commits"
sleep 1

# Test 10: Check run lint failure (fork PR in pull_requests[] — should be ignored)
send_and_check "$PAYLOAD_DIR/checkrun_lint_failure.json"
assert_output "Check run lint failure (fork PR ignored)" "lint failed"
assert_not_output "Check run lint failure rejects fork PR" "PR #6 '"
sleep 1

# Test 11: Check run lint success (fork PR in pull_requests[] — should be ignored)
send_and_check "$PAYLOAD_DIR/checkrun_lint_success.json"
assert_output "Check run lint success (fork PR ignored)" "lint passed"
assert_not_output "Check run lint success rejects fork PR" "PR #6 '"
sleep 1

# Test 12: Check run lint failure (same-repo PR)
send_and_check "$PAYLOAD_DIR/checkrun_lint_failure_same_repo.json"
assert_output "Check run lint failure (same-repo PR)" "lint failed for PR #42"
sleep 1

# Test 13: Check run lint success (same-repo PR)
send_and_check "$PAYLOAD_DIR/checkrun_lint_success_same_repo.json"
assert_output "Check run lint success (same-repo PR)" "lint passed for PR #42"

dump_observer_log

echo ""
