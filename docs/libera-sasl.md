# Libera.Chat SASL setup

Lunabot uses SASL PLAIN inside its verified TLS connection. SASL completes
during IRC registration, so Libera.Chat applies the account and cloak before
the bot joins a channel.

## Test the account with Irssi first

Use a recent Irssi release. Replace the example account name and password, and
use a separate network name for each bot account you want to test:

```text
/network add -sasl_username lunabot -sasl_password YOUR_NICKSERV_PASSWORD -sasl_mechanism PLAIN LiberaLunabot
/server add -auto -net LiberaLunabot -tls -tls_verify irc.libera.chat 6697
/connect LiberaLunabot
```

The connection window should report that SASL authentication succeeded. Check
the account and cloak with:

```text
/whois your-current-nick
/msg NickServ INFO lunabot
```

Once confirmed, save the configuration:

```text
/save
```

Repeat with another network name and account, such as `LiberaCodybot` and
`codybot`. Irssi stores the SASL password in `~/.irssi/config`; keep that file
private (`chmod 600 ~/.irssi/config`). If the account does not exist yet, follow
Libera.Chat's account-registration guide and verify its email before testing
SASL.

## Run lunabot or codybot

Set the account name explicitly when it differs from the configured nick:

```sh
docker run -d \
  --name lunabot \
  --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  -e LUNABOT_SASL_USERNAME=lunabot \
  -e LUNABOT_SASL_PASSWORD='YOUR_NICKSERV_PASSWORD' \
  -e LUNABOT_WEBHOOK_SECRET='YOUR_GITHUB_WEBHOOK_SECRET' \
  esselfe/lunabot
```

For `codybot`, use its own account credentials, container name, configuration,
and host-side webhook port, for example `127.0.0.1:3001:3000`.

For long-running deployments, mounting root-readable `.passwd` and `.secret`
files into `/app` avoids exposing secrets through `docker inspect`:

```sh
install -d -m 700 /srv/lunabot/lunabot
printf '%s\n' 'YOUR_NICKSERV_PASSWORD' > /srv/lunabot/lunabot/.passwd
printf '%s\n' 'YOUR_GITHUB_WEBHOOK_SECRET' > /srv/lunabot/lunabot/.secret
chmod 600 /srv/lunabot/lunabot/.passwd /srv/lunabot/lunabot/.secret

docker run -d \
  --name lunabot \
  --restart unless-stopped \
  -p 127.0.0.1:3000:3000 \
  -e LUNABOT_SASL_USERNAME=lunabot \
  -v /srv/lunabot/lunabot/.passwd:/app/.passwd:ro \
  -v /srv/lunabot/lunabot/.secret:/app/.secret:ro \
  esselfe/lunabot
```

Verify startup ordering in the container logs:

```sh
docker logs lunabot 2>&1 | grep -E 'SASL authentication successful|JOIN '
```

`SASL authentication successful` must appear before `JOIN`. If SASL fails,
lunabot deliberately disconnects and never joins anonymously.
