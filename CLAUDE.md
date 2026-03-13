# CLAUDE.md — Lunabot Project Guide

## Project Overview

Lunabot is a C IRC bot (GPLv3, author: Stephane Fontaine) that relays GitHub webhook events to an IRC channel over TLS. It was written for the Lunar-Linux project but is configurable for any GitHub project.

**Version:** 0.5.6
**Language:** C (C17 standard)
**Build system:** GNU Make
**Dependencies:** gcc, libmicrohttpd, jansson, openssl, pthread

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
- `struct GlobalVariables` — single global state struct holding all runtime config (IRC connection, SSL pointer, webhook port, flags, etc.)
- `struct RawLine` — parsed IRC message fields (nick, username, host, command, channel, text)
- IRC color code defines (`GREEN`, `RED`, `CYAN`, etc.) using mIRC color format (`\003NN`)
- Log direction constants: `LOCAL` (internal), `IN` (received), `OUT` (sent)

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
Calls `dlclose()` on the old handle, then `dlopen("./liblunabot.so", ...)`. Re-resolves all 6 function pointers: `Log`, `FreeRawLine`, `ParseRawLine`, `SendIrcMessage`, `ReplayJsonPayload`, `liblunabotInit`. Also links the main program's `globals` struct into the library via the exported `libglobals` pointer.

**`IrcConnect()` (thread):**
- Creates a TCP socket, resolves the IRC server hostname via `getaddrinfo()`
- Connects, sets up OpenSSL TLS (minimum TLS 1.2, no compression)
- Sends `NICK`, `USER`, then `PRIVMSG NickServ :IDENTIFY <password>`
  - Password read from `LUNABOT_NICKSERV_PASSWORD` env var, or `.passwd` file
- Joins the configured channel
- Enters a read loop: handles `PING` → `PONG` internally; logs everything else via `Log_fp()`
- On disconnect, sets `globals.irc_connected = 0` (main loop will reconnect)

**`ConsoleReadLoop()` (thread):**
Reads stdin line by line:
- `exit` / `quit` / `qw` → exits the program
- `reload` → calls `ReloadLibrary()` then `liblunabotInit_fp()` (hot-reload)
- `replay <filename>` → calls `ReplayJsonPayload_fp(filename)` (test webhook JSON from file)
- Anything else → sends as a raw IRC command over SSL

**`ParseConfig()`:** Reads `lunabot.conf.json`. All fields are optional; missing fields fall back to defaults.

**`GetIP()`:** Resolves a hostname to IPv4 using `getaddrinfo()`, stores result in `globals.irc_server_ip`.

---

### `src/liblunabot.c` — Shared Library
All webhook processing, IRC message sending, health checks, and IRC line parsing.

**`libglobals`:** A pointer to the main program's `globals` struct, set by `ReloadLibrary()` on each load.

**`Log(direction, text)`:**
Writes a timestamped line to stdout (with ANSI cyan color) and to `lunabot.log` (or configured log file). Format: `YYYYMMDD-HH:MM:SS.usec <<##text##`. Direction symbols: `||` local, `<<` in, `>>` out.

**`SendIrcMessage(message)`:**
Formats `PRIVMSG #channel :message\r\n` and writes to SSL socket. Also calls `Log(OUT, ...)`.

**`VerifySignature_func(payload, signature)`:**
Computes HMAC-SHA256 of the payload using the webhook secret (from `LUNABOT_WEBHOOK_SECRET` env var or `.secret` file). Compares against the GitHub-provided `X-Hub-Signature-256` header. Uses a constant-time comparison loop to mitigate timing attacks. Returns 0 on success, 1 on failure.

**`SanitizeMessage(root, msg)`:**
Extracts a JSON string value and replaces control characters (`\n`, `\r`, `\a`, `\033`) with spaces to prevent IRC injection.

**`StripGithubApiPrefix(url)`:**
Strips `https://api.github.com/repos/` prefix from URLs, leaving the `owner/repo/...` path for constructing `https://github.com/` URLs.

**`ParseJsonData(json_data)`:**
The main webhook event dispatcher. Parses the JSON payload and handles four event categories:

1. **CI status events** (payload has `"context"` field):
   - Checks `context` matches `ci_context_name` config
   - Skips events with empty `target_url` (first GitHub status event is incomplete)
   - Formats IRC messages for `pending` (yellow, optionally skipped), `success` (green), `failure`/`error` (red)

2. **Pull request events** (payload has `"action"` + `"pull_request"` fields):
   - `labeled` / `unlabeled`: Posts label add/remove notifications; can filter to `only_core_labels` (moonbase-core repo only) or skip all via `ignore_labels`
   - `opened`: Posts new PR notification with title, author, URL
   - `closed`: Posts either "Merged PR" (cyan) or "Closed PR" (red) depending on the `merged` field

3. **Check run events** (payload has `"check_run"` field):
   - A two-stage mechanism with a 60-second timeout flag (`processing_lint_event`):
     - Stage 1: A `lint` check run with `conclusion: "failure"` sets `processing_lint_event = 1` and starts a timeout thread
     - Stage 2: When `processing_lint_event` is set and a `comment` check run with `status: "completed"` arrives, it extracts the PR URL from `check_suite.pull_requests[0].url` and posts a "check run failed" IRC message
   - This two-stage design is needed because the `lint` event itself does not contain a PR URL; the URL comes in a subsequent `comment` event

4. **Push commit events** (payload has `"refs"` + `"commits"` fields):
   - Only processed if `ignore_commits` is false and ref is `refs/head/master`
   - Posts each commit's message, committer username, and URL

Falls through to a "Got webhook data without a conditional branch" log message if no branch matched.

**`ReplayJsonPayload(filename)`:**
Reads a JSON file from disk and feeds it directly to `ParseJsonData()`. Used for testing without a live GitHub webhook.

**`WebhookCallback()`** (libmicrohttpd request handler):
- **GET `/health`**: Rate-limited health check. Sends `PING NickServ` over IRC, waits up to 10 seconds for a `PONG` response (detected in `ParseRawLine`). Returns 200 if pong received, 500 on timeout. Returns 200 immediately (rate-limited) if called too frequently.
- **POST (all other paths)**: Validates `X-Hub-Signature-256` header presence, accumulates chunked POST body into a dynamically growing buffer, then calls `VerifySignature_func()` and `ParseJsonData()` once the full body is received.
- Non-POST, non-GET requests return 401.

**`ParseRawLine(line)`:**
Parses IRC protocol lines in the format `:nick!~user@host COMMAND #channel :text`.
- Skips NickServ/ChanServ messages, PING, ERROR, numeric server replies, MODE, NOTICE
- Detects `PONG` replies and sets `health_check = 2` (signals the health check poller)
- Returns a heap-allocated `struct RawLine` (caller must free with `FreeRawLine()`)
- Note: `ParseRawLine` is defined in the library but currently commented out in the IRC read loop in `lunabot.c`

**`liblunabotInit()`:**
Stops any running MHD daemon, starts a new one on `webhook_port`. Called at startup and on `reload`. Initializes `health_check_tprev` so the first health check is immediately available.

**Lint event threading (`ProcessLintEventCallback`, `ProcessLintEventStart`):**
A detached thread that watches `processing_lint_event`. If it doesn't get cleared (by receiving the `comment` check run event) within 60 seconds, it clears the flag itself. Uses `pthread_mutex_t` for safe atomic access alongside `atomic_uint`.

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
| `ci_context_name` | `continuous-integration/jenkins/pr-head` | CI context string to match |

**CLI flags** override config values: `--debug/-d`, `--channel/-c`, `--nick/-n`, `--irc-port/-p`, `--irc-server/-s`, `--webhook-port/-w`, `--log/-l`, `--context/-C`.

**Credentials** (required at runtime):
- NickServ password: `LUNABOT_NICKSERV_PASSWORD` env var or `.passwd` file
- Webhook secret: `LUNABOT_WEBHOOK_SECRET` env var or `.secret` file

---

## Build

```sh
make          # builds liblunabot.so and lunabot
make clean    # removes obj/, liblunabot.so, lunabot
```

The binary links against: `-lpthread -lmicrohttpd -ljansson -lssl -lcrypto -ldl`

---

## Runtime Behavior Notes

- The bot auto-reconnects to IRC if the connection drops (main loop checks `irc_connected` every 5 seconds).
- HTTPS is not supported on the webhook listener; use a reverse proxy (nginx/Apache) for HTTPS.
- The `reload` console command hot-reloads `liblunabot.so` without restarting, re-initializing the webhook server.
- IRC server defaults to `irc.libera.chat:6697`.
- All timestamps in logs are UTC.
