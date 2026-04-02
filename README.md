# Lunabot - IRC bot for Github webhooks

Lunabot is a C IRC bot (GPLv3) that relays GitHub webhook events to an IRC channel over TLS. While primarily developed for the Lunar-Linux project, it is configurable for any GitHub project.

## Features

- Connects to an IRC server over TLS with OpenSSL.
- Sends messages in the channel for:
  - New pull request.
  - Pending CI build (optional).
  - CI build status, Failed or Success.
  - Lint check run results (pass/fail) with PR title lookup.
  - Closed PR.
  - Merged PR.
  - Label operations on pull requests (optional).
  - Push commits (optional).
- Listens for GitHub webhook events via an embedded HTTP server.
- Verifies GitHub webhook signatures (HMAC-SHA256).
- Parses and formats repository events before sending them to the IRC channel.
- Orchestration health checks via the `/health` HTTP endpoint.
- Hot-reloads the webhook processing library at runtime without restarting (`reload` console command).
- Auto-reconnects to IRC if the connection drops.

## Architecture

The project compiles into two artifacts:

- **`lunabot`** — the main executable
- **`liblunabot.so`** — a shared library loaded at runtime via `dlopen()`

The library can be reloaded at runtime without restarting the bot (type `reload` in the terminal). This hot-reload pattern lets you update the webhook parsing logic live.

## Requirements

To compile and run lunabot, you will need the following dependencies installed:

- autoconf, automake, libtool (to generate the build system)
- gcc (The GNU C compiler)
- libmicrohttpd (for the webhook server)
- jansson (for the webhook JSON data parsing)
- openssl (for secure IRC connections and signature verification)
- libcurl (for GitHub API requests)
- pthread (for multithreading support)

## Build and run

Run `autogen.sh` once to generate the build system, then configure and build:

```sh
./autogen.sh       # generate configure script (requires autoconf, automake, libtool)
./configure        # detect dependencies via pkg-config
make               # builds src/lib/.libs/liblunabot.so and lunabot
```

You will need to provide credentials at runtime. Either set environment variables:

- `LUNABOT_NICKSERV_PASSWORD` — IRC NickServ password
- `LUNABOT_WEBHOOK_SECRET` — GitHub webhook secret

Or place them in `.passwd` and `.secret` files respectively.

To run the program, type `./lunabot`.

## Configuration

All settings are optional; missing fields fall back to defaults. Edit `lunabot.conf.json`:

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

CLI flags override config values: `--debug/-d`, `--channel/-c`, `--nick/-n`, `--irc-port/-p`, `--irc-server/-s`, `--webhook-port/-w`, `--log/-l`, `--context/-C`.

IRC server defaults to `irc.libera.chat:6697`.

## Console commands

While the bot is running, type commands at the terminal:

- `reload` — hot-reloads `liblunabot.so` and re-initializes the webhook server
- `replay <filename>` — feeds a JSON payload file directly into the webhook processor (for testing)
- `exit` / `quit` / `qw` — exits the program
- Any other input is sent as a raw IRC command

## Integration Tests

The `test/` directory contains a full Docker-based integration test environment.

```sh
make test           # build then run integration tests (requires Docker with compose plugin)
make test-clean     # tear down test containers and volumes
```

Pass `-v` / `--verbose` to `test/run-tests.sh` directly to dump the captured IRC output after the run.

Test payloads live in `test/payloads/` (JSON files for each webhook event type). The runner signs each with HMAC-SHA256 and POSTs them to lunabot, then checks the IRC output for expected message substrings.

## Notes

HTTPS is not implemented for the webhook listener, but you can use a reverse proxy (nginx/Apache) to forward requests to localhost over HTTPS.

## Authors

- Stephane Fontaine (esselfe) — original author
- Stefan Wold (Ratler) — autotools build system, integration test infrastructure, check run refactor, GitHub API integration, SonarCloud quality fixes
