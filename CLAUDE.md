# CLAUDE.md — Lunabot Project Guide

## Project Overview

Lunabot is a C IRC bot (GPLv3, author: Stephane Fontaine) that relays GitHub webhook events to an IRC channel over TLS. It was written for the Lunar-Linux project but is configurable for any GitHub project.

**Version:** 0.5.6
**Language:** C (C17 standard)
**Build system:** Autotools (autoconf/automake/libtool)
**Dependencies:** gcc, libmicrohttpd, jansson, openssl, libcurl, pthread

**Contributors:**
- Stephane Fontaine (esselfe) — original author
- Stefan Wold (Ratler) — autotools build system, integration test infrastructure, check run refactor, GitHub API integration, SonarCloud quality fixes

---

## Architecture

The project compiles into two artifacts:

- **`lunabot`** — the main executable (from `src/lunabot.c`)
- **`liblunabot.so`** — a shared library (from `src/liblunabot.c`) loaded at runtime via `dlopen()`

The split is intentional: the library can be reloaded at runtime without restarting the bot (type `reload` in the terminal). This hot-reload pattern lets you update the webhook parsing logic live.

---

## Source Files

### `src/lunabot.h`
Defines shared data structures and constants:
- `struct IrcConfig` — IRC-specific fields: `irc_server_hostname`, `irc_server_ip`, `irc_server_port`, `irc_sock`. Embedded as `irc` inside `GlobalVariables`.
- `struct GlobalVariables` — single global state struct holding all runtime config (IRC connection via `irc`, SSL pointer, webhook port, flags, etc.)
- IRC color code defines (`GREEN`, `RED`, `CYAN`, etc.) using mIRC color format (`\003NN`)
- Log direction constants: `LOCAL` (internal), `IN` (received), `OUT` (sent)
- `DEFAULT_CONTEXT_NAME` defaults to `"default"`

### `src/lunabot.c` — Main Program
Startup, configuration, IRC connection, console loop.

**Startup sequence (`main`):**
1. `ReloadLibrary()` — dynamically loads `liblunabot.so`, resolves all function pointers
2. `ParseConfig()` — reads `lunabot.conf.json` using jansson
3. `ParseArgs()` — processes CLI arguments (override config values)
4. Fills in defaults for any unset values
5. `ConsoleReadLoopStart()` — starts a detached thread reading stdin
6. `liblunabotInit_fp()` — initializes the webhook HTTP server (from library)
7. Main loop: monitors `irc_connected`; if disconnected, calls `IrcConnectStart()`

**`ReloadLibrary()`:**
Calls `dlclose()` on the old handle, then tries `dlopen("./src/lib/.libs/liblunabot.so", ...)` first (libtool in-tree build path), falling back to `dlopen("liblunabot.so", ...)` for installed deployments. Re-resolves all 4 function pointers: `Log`, `SendIrcMessage`, `ReplayJsonPayload`, `liblunabotInit`. Also links the main program's `globals` struct into the library via the exported `libglobals` pointer.

**`IrcConnect()` (thread):**
- Creates a TCP socket, resolves the IRC server hostname via `getaddrinfo()`
- Connects, sets up OpenSSL TLS (minimum TLS 1.2, no compression)
- Sends `NICK`, `USER`, then `PRIVMSG NickServ :IDENTIFY <password>`
  - Password read from `LUNABOT_NICKSERV_PASSWORD` env var, or `.passwd` file
- Joins the configured channel
- Enters a read loop: handles `PING` → `PONG` internally; logs everything else via `Log_fp()`
- On disconnect, sets `globals.irc_connected = 0` (main loop will reconnect)
- IRC fields accessed via `globals.irc.*` (the nested `struct IrcConfig`)

**`ConsoleReadLoop()` (thread):**
Reads stdin line by line:
- `exit` / `quit` / `qw` → exits the program
- `reload` → calls `ReloadLibrary()` then `liblunabotInit_fp()` (hot-reload)
- `replay <filename>` → calls `ReplayJsonPayload_fp(filename)` (test webhook JSON from file)
- Anything else → sends as a raw IRC command over SSL

**`ParseConfig()`:** Reads `lunabot.conf.json`. All fields are optional; missing fields fall back to defaults.

**`GetIP()`:** Resolves a hostname to IPv4 using `getaddrinfo()`, stores result in `globals.irc.irc_server_ip`.

---

### `src/lib/` — Shared Library Sources

The shared library (`liblunabot.so`) is compiled from multiple source files in `src/lib/`. The entry point file is `src/lib/liblunabot.c`; all other modules are linked into the same `.so`.

**`libglobals`** (declared in `liblunabot.c`): A pointer to the main program's `globals` struct, set by `ReloadLibrary()` on each load. All library modules access runtime state through this pointer.

---

**`src/lib/liblunabot.c`** — Library entry point.

**`liblunabotInit()`:**
Stops any running MHD daemon, starts a new one on `webhook_port`. Called at startup and on `reload`. Initializes `health_check_tprev` so the first health check is immediately available.

---

**`src/lib/log.c`**

**`Log(direction, text)`:**
Writes a timestamped line to stdout (with ANSI cyan color) and to `lunabot.log` (or configured log file). Format: `YYYYMMDD-HH:MM:SS.usec <<##text##`. Direction symbols: `||` local, `<<` in, `>>` out.

---

**`src/lib/irc.c`**

**`SendIrcMessage(message)`:**
Formats `PRIVMSG #channel :message\r\n` and writes to SSL socket. Also calls `Log(OUT, ...)`.

---

**`src/lib/verify-signature.c`**

**`VerifySignature_func(payload, signature)`:**
Computes HMAC-SHA256 of the payload using the webhook secret (from `LUNABOT_WEBHOOK_SECRET` env var or `.secret` file). Compares against the GitHub-provided `X-Hub-Signature-256` header. Uses a constant-time comparison loop to mitigate timing attacks. Returns 0 on success, 1 on failure.

---

**`src/lib/sanitize.c`**

**`SanitizeMessage(root, msg)`:**
Extracts a JSON string value and replaces control characters (`\n`, `\r`, `\a`, `\033`) and shell-sensitive characters with spaces to prevent IRC injection.

---

**`src/lib/api.c`** — GitHub API helpers (libcurl-based).

- `CurlWriteCallback()` / `struct CurlBuffer` — accumulates HTTP response data for libcurl.
- `FetchGithubApi(url)` — performs a GET request to the GitHub API, returns parsed jansson JSON. Caller must `json_decref()` the result.
- `FetchPullRequestTitle(repo_full_name, pr_number)` — fetches PR title from `GET /repos/{owner}/{repo}/pulls/{number}`.
- `FetchPullRequestBySha(repo_full_name, head_sha, &out_number, &out_title)` — looks up a PR by commit SHA. Tries `GET /repos/{owner}/{repo}/commits/{sha}/pulls` first; falls back to the search API (`GET /search/issues?q=repo:...+type:pr+SHA:...`) for fork PRs where the commits endpoint returns an empty array. Sets `out_number` and `out_title` (caller must free). Returns 0 on success.

---

**`src/lib/json.c`** — Webhook event dispatcher.

**`ShouldSkipLabelEvent(root)`** (static):
Helper that returns 1 (skip) if `ignore_labels` is set, or if `only_core_labels` is set and the event's `repository.name` is not `moonbase-core`. Returns 0 to process.

**`ParseJsonData(json_data)`:**
The main webhook event dispatcher. Parses the JSON payload and handles four event categories:

1. **CI status events** (payload has `"context"` field):
   - Checks `context` matches `ci_context_name` config
   - Skips events with empty `target_url` (first GitHub status event is incomplete)
   - Formats IRC messages for `pending` (yellow, optionally skipped), `success` (green), `failure`/`error` (red)

2. **Pull request events** (payload has `"action"` + `"pull_request"` fields):
   - `labeled` / `unlabeled`: Posts label add/remove notifications; filtered via `ShouldSkipLabelEvent()`
   - `opened`: Posts new PR notification with title, author, URL
   - `closed`: Posts either "Merged PR" (cyan) or "Closed PR" (red) depending on the `merged` field

3. **Check run events** (payload has `"check_run"` field):
   - Handles only `lint` check runs with `status: "completed"`
   - Extracts `pr_number` from `check_run.pull_requests[0].number` if present
   - If `pull_requests[]` is empty (fork PRs), calls `FetchPullRequestBySha()` using `check_run.head_sha`
   - If `pr_number` is known but title is not yet fetched, calls `FetchPullRequestTitle()`
   - Reports `failure` (red) as "lint failed for PR #N 'title' - URL | check_url"
   - Reports `success` (green) as "lint passed for PR #N 'title' - URL"
   - Falls back to a simpler message without PR details if lookup fails

4. **Push commit events** (payload has `"refs"` + `"commits"` fields):
   - Only processed if `ignore_commits` is false and ref is `refs/head/master`
   - Posts each commit's message, committer username, and URL

Falls through to a "Got webhook data without a conditional branch" log message if no branch matched.

**`ReplayJsonPayload(filename)`:**
Reads a JSON file from disk and feeds it directly to `ParseJsonData()`. Used for testing without a live GitHub webhook.

---

**`src/lib/health-check.c`**

**`HandleHealthCheck(connection)`:**
Rate-limited health check handler. Sends `PING NickServ` over IRC, waits up to 10 seconds for a `PONG` response (detected via `health_check` flag in `globals`). Returns 200 if pong received, 500 on timeout. Returns 200 immediately (rate-limited) if called too frequently. The timeout is implemented via a detached `HealthCheckTimeoutFunc` thread.

---

**`src/lib/webhook.c`**

**`WebhookCallback()`** (libmicrohttpd request handler):
- **GET `/health`**: Delegates to `HandleHealthCheck()`.
- **POST (all other paths)**: Validates `X-Hub-Signature-256` header presence, accumulates chunked POST body into a dynamically growing buffer, then calls `VerifySignature_func()` and `ParseJsonData()` once the full body is received.
- Non-POST, non-GET requests return 401.

---

## Configuration

**`lunabot.conf.json`** (all optional, defaults apply):

| Key | Default | Description |
|-----|---------|-------------|
| `debug` | false | Enable verbose debug output |
| `log_filename` | `lunabot.log` | Log file path |
| `disable_logging` | false | Suppress log file writes |
| `nick` | `lunabot` | IRC nick |
| `channel` | `#lunar-lunabot` | IRC channel to join and message |
| `health_check_wait` | 15 | Minimum seconds between health checks |
| `only_core_labels` | false | Only relay labels for `moonbase-core` repo |
| `ignore_labels` | false | Suppress all label events |
| `ignore_pending` | true | Suppress CI "pending" status events |
| `ignore_commits` | true | Suppress push commit events |
| `webhook_port` | 3000 | HTTP port for webhook listener |
| `ci_context_name` | `default` | CI context string to match |

**CLI flags** override config values: `--debug/-d`, `--channel/-c`, `--nick/-n`, `--irc-port/-p`, `--irc-server/-s`, `--webhook-port/-w`, `--log/-l`, `--context/-C`.

**Credentials** (required at runtime):
- NickServ password: `LUNABOT_NICKSERV_PASSWORD` env var or `.passwd` file
- Webhook secret: `LUNABOT_WEBHOOK_SECRET` env var or `.secret` file

---

## Build

The project uses autotools. Run `autogen.sh` once to generate the build system, then configure and build normally:

```sh
./autogen.sh       # generate configure script (requires autoconf, automake, libtool)
./configure        # detect dependencies via pkg-config
make               # builds src/lib/.libs/liblunabot.so and lunabot
make clean         # remove build artifacts
make maintainer-clean  # remove all autotools-generated files too
```

The old hand-written Makefile is preserved as `Makefile.simple` for reference.

The library is built into `src/lib/.libs/liblunabot.so` by libtool during in-tree builds. `ReloadLibrary()` tries that path first, then falls back to the bare name for installed deployments.

The binary links against: `-lpthread -lmicrohttpd -ljansson -lssl -lcrypto -lcurl -ldl`

---

## Integration Tests

The `test/` directory contains a full Docker-based integration test environment added by Stefan Wold.

**Components:**
- `test/Dockerfile.lunabot` — multi-stage Docker build for lunabot
- `test/Dockerfile.ergo` — Ergo IRC server container
- `test/ergo/ircd.yaml` — Ergo IRC server configuration
- `test/ergo/generate-certs.sh` — generates TLS certs for Ergo
- `test/docker-compose.yml` — orchestrates lunabot + Ergo + observer containers
- `test/observer/observer.c` — C IRC client that joins the channel and prints all PRIVMSG to stdout; used by the test runner to capture lunabot's output
- `test/run-tests.sh` — shell test runner: sends HMAC-signed webhook payloads via curl and asserts expected substrings appear in the observer's IRC output within a timeout

**Running tests:**
```sh
make test           # build then run integration tests (requires Docker with compose plugin)
make test-clean     # tear down test containers and volumes
```

Pass `-v` / `--verbose` to `run-tests.sh` directly to dump the captured IRC output after the run (mIRC color codes are stripped for readability).

**Test payloads** live in `test/payloads/` (JSON files for each webhook event type). The runner signs each with HMAC-SHA256 using the test secret and POSTs them to lunabot, then polls the observer log for expected IRC message substrings.

The observer supports both TLS and plain IRC connections (`--tls` / `--no-tls` flags) and exits after a configurable timeout.

---

## Runtime Behavior Notes

- The bot auto-reconnects to IRC if the connection drops (main loop checks `irc_connected` every 5 seconds).
- HTTPS is not supported on the webhook listener; use a reverse proxy (nginx/Apache) for HTTPS.
- The `reload` console command hot-reloads `liblunabot.so` without restarting, re-initializing the webhook server.
- IRC server defaults to `irc.libera.chat:6697`.
- All timestamps in logs are UTC.
