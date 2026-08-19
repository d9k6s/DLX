<!--
 * @Author: Vincent Young
 * @Date: 2022-10-18 07:32:29
 * @LastEditors: Vincent Yang
 * @LastEditTime: 2026-07-08 00:00:00
 * @FilePath: /DLX/README.md
 * @Telegram: https://t.me/missuo
 * 
 * Copyright © 2022 by Vincent, All Rights Reserved. 
-->

# DLX

[![GitHub Workflow][1]](https://github.com/OwO-Network/DLX/actions)
[![Go Version][2]](https://github.com/OwO-Network/DLX/blob/main/go.mod)
[![Go Report][3]](https://goreportcard.com/badge/github.com/OwO-Network/DLX)
[![GitHub License][4]](https://github.com/OwO-Network/DLX/blob/main/LICENSE)
[![Docker Pulls][5]](https://hub.docker.com/r/missuo/deeplx)
[![Releases][6]](https://github.com/OwO-Network/DLX/releases)

[1]: https://img.shields.io/github/actions/workflow/status/OwO-Network/DLX/release.yaml?logo=github
[2]: https://img.shields.io/github/go-mod/go-version/OwO-Network/DLX?logo=go
[3]: https://goreportcard.com/badge/github.com/OwO-Network/DLX
[4]: https://img.shields.io/github/license/OwO-Network/DLX
[5]: https://img.shields.io/docker/pulls/missuo/deeplx?logo=docker
[6]: https://img.shields.io/github/v/release/OwO-Network/DLX?logo=smartthings

> [!IMPORTANT]
> **Disclaimer:** DLX is an independent, open-source project. It is **not** an official DeepL product, and it is **not** affiliated with, endorsed by, or sponsored by DeepL SE in any way. "DeepL" is a registered trademark of DeepL SE. Any reference to DeepL in this repository is made solely to describe interoperability with the DeepL translation service.

## Why was this project renamed?

In July 2026, we received a trademark notice forwarded by GitHub Trust & Safety, submitted on behalf of DeepL SE. The notice stated that this project's former name, "DeepLX", contained the registered trademark "DeepL" and might cause confusion about whether the project is authorized or endorsed by DeepL SE.

It never was, and it never claimed to be. To resolve the matter and remove any possible confusion, we renamed the repository to **DLX** and removed DeepL branding from the project. To state it plainly one more time: **this project is not an official DeepL project and has no relationship with DeepL SE whatsoever.**

DLX is a self-hosted translation API server written in Go. It exposes a simple HTTP API on port `1188`.

## Usage

### Docker

Docker Hub and GHCR image names remain `deeplx` (only the GitHub repository was renamed to DLX):

```bash
docker run -d -p 1188:1188 ghcr.io/owo-network/deeplx:latest
# or: docker run -d -p 1188:1188 missuo/deeplx:latest
```

Or use the provided [`compose.yaml`](compose.yaml):

```bash
docker compose up -d
```

### Binary

Download the binary for your platform from [Releases](https://github.com/OwO-Network/DLX/releases) and run it (artifact names remain `deeplx_*`):

```bash
./deeplx
```

### Translate

```bash
curl -X POST http://localhost:1188/translate \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello, world!", "source_lang": "EN", "target_lang": "ZH"}'
```

### DeepL Pro OAuth token lifecycle

`/v1/translate` uses a DeepL Pro OAuth access token. A static access token can
still be supplied through `DL_SESSION`. To keep Pro translation working after
that short-lived token expires, also provide its refresh token and a persistent
state file:

The authenticated `/v1/translate` route accepts one source text up to 300,000
UTF-16 code units, matching the client-side limit in DeepL's official Chrome
extension. Supplementary characters such as emoji count as two units. The
anonymous `/translate` and `/v2/translate` routes retain their 1,500-character
limit. DeepL may still return `413` if its current upstream payload limit is
lower.

```yaml
services:
  deeplx:
    image: ghcr.io/d9k6s/deeplx:latest
    environment:
      TOKEN: "replace-with-your-DLX-access-token"
      DL_SESSION: "replace-with-the-current-DeepL-access-token"
      DL_REFRESH_TOKEN: "replace-with-the-DeepL-refresh-token"
      DL_TOKEN_STORE: "/data/deepl-oauth.json"
    volumes:
      - deeplx-oauth:/data

volumes:
  deeplx-oauth:
```

When `DL_REFRESH_TOKEN` is configured, DLX follows the current DeepL Chrome
extension flow: it discovers `token_endpoint` from
`https://auth.deepl.com/.well-known/openid-configuration`, refreshes with
`client_id=chromeExtension`, refreshes tokens that have less than 60 seconds
remaining, and retries one translation after an upstream `401`. Only an HTTPS
token endpoint is accepted. Rotated access, refresh, and ID tokens are written
atomically to `DL_TOKEN_STORE` with owner-only permissions so they survive
container restarts.

When the state file does not exist yet, the first Pro request immediately
refreshes and persists the supplied token generation. Use a dedicated DeepL
login session for DLX; allowing the browser extension and DLX to rotate the
same refresh token can invalidate one of them.

`DL_TOKEN_STORE` is strongly recommended because DeepL rotates refresh tokens.
Do not commit any OAuth token or the state file to source control, and do not
put `Bearer ` in front of `DL_SESSION`.

Docker logs report the OAuth lifecycle without exposing credential values. They
include whether access and refresh tokens are configured, whether persisted
state was loaded, refresh start/success/failure events, the refresh reason,
expiry time, rotation/persistence status, and a sanitized OAuth error code when
DeepL rejects a refresh. Request logging also replaces the value of a `token`
query parameter with `REDACTED`. Prefer the `Authorization: Bearer` header so
the DLX access token is not placed in URLs outside the application either.

## Discussion Group
[Telegram Group](https://t.me/+8KDGHKJCxEVkNzll)

## Acknowledgements

### Contributors

<a href="https://github.com/OwO-Network/DLX/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=OwO-Network/DLX&anon=0" />
</a>

## Activity
![Alt](https://repobeats.axiom.co/api/embed/5f473f85db27cb30028a2f3db7a560f3577a4860.svg "Repobeats analytics image")

## License
[MIT](LICENSE)
