# wecom-relay

A lightweight public-facing relay service that bridges WeCom's HTTP callbacks to an internal SOARAI deployment.

## Problem it solves

WeCom's interactive template cards (`button_interaction`) deliver user responses via an HTTP POST to a callback URL registered in the WeCom admin console. If SOARAI runs on an internal host with no public IP, WeCom cannot reach it directly. This relay sits on a public server, receives those callbacks, and lets SOARAI poll for the result.

```
[WeCom user clicks button]
        │
        ▼
[WeCom server]  ──POST──▶  [wecom-relay :8000]  ◀──poll──  [SOARAI internal]
                            (public server)
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Returns `{"status": "ok", "pending": N}`. Used by SOARAI's connector test. |
| `GET` | `/wechat/callback` | WeCom URL ownership verification (one-time, triggered when saving the callback URL in the admin console). |
| `POST` | `/wechat/callback` | Receives encrypted WeCom events. Decrypts, parses `button_interaction` responses, stores them by `task_id`. |
| `GET` | `/relay/response/{task_id}` | SOARAI polls this. Returns `404` until the user has clicked a button, then returns the response JSON. |
| `DELETE` | `/relay/response/{task_id}` | SOARAI calls this to consume (remove) a response after reading it. |

### Response JSON shape

```json
{
  "task_id": "a1b2c3d4",
  "response": "Yes",
  "user_id": "zhangsan",
  "code": "ResponseCode_from_WeCom",
  "received_at": 1716192000.123
}
```

`code` is WeCom's `ResponseCode` (valid ~5 minutes). SOARAI uses it to call `interactive/taskcard/update` and replace the card with reply text.

## Configuration

All configuration is via environment variables.

| Variable | Required | Description |
|----------|----------|-------------|
| `WECOM_TOKEN` | Yes | Callback token from WeCom admin console → Application → Receive Messages |
| `WECOM_ENCODING_AES_KEY` | Yes | 43-character AES key from the same page |
| `WECOM_CORP_ID` | Yes | Enterprise Corp ID from WeCom admin console → My Enterprise |
| `RELAY_API_SECRET` | No | Shared secret sent as `X-Relay-Secret` header by SOARAI. Strongly recommended in production to prevent unauthorized polling. |
| `RESPONSE_TTL_SECONDS` | No | How long responses are kept in memory before automatic cleanup. Default: `86400` (24 hours). |
| `WECOM_CORP_SECRET` | No | Corp secret (WeCom admin → App Management → [App] → Secret). Required for immediate card-disable. |
| `WECOM_AGENT_ID` | No | App agent ID (WeCom admin → App Management → [App]). Required together with `WECOM_CORP_SECRET`. |

### Immediate card-disable (optional)

When `WECOM_CORP_SECRET` and `WECOM_AGENT_ID` are both set, the relay calls WeCom's `interactive/taskcard/update` API immediately after receiving a button click. This replaces the button area with the selected button's label, preventing the user from clicking again while SOARAI processes the response.

Without these variables the feature is disabled and the card remains interactive until SOARAI sends its reply.

## Running with Docker Compose

1. Create a `.env` file next to `compose.yaml`:

```env
WECOM_TOKEN=your_token_here
WECOM_ENCODING_AES_KEY=your_43char_key_here
WECOM_CORP_ID=wwXXXXXXXXXXXXXX
RELAY_API_SECRET=a_strong_random_secret
```

2. Start the service:

```bash
docker compose up -d
```

The service listens on port `8000`. Put it behind a reverse proxy (nginx, Caddy, etc.) with HTTPS before registering the URL in WeCom.

## WeCom admin console setup

1. Go to **My Enterprise → Application Management → [Your App] → Receive Messages**.
2. Set the callback URL to `https://your-public-domain/wechat/callback`.
3. Enter the same `WECOM_TOKEN` and `WECOM_ENCODING_AES_KEY` values you put in `.env`.
4. Click **Save** — WeCom will send a GET verification request immediately. The relay handles this automatically.

## SOARAI connector configuration

In the WeCom connector credentials, set:

| Field | Value |
|-------|-------|
| `relay_url` | `https://your-public-domain` (no trailing slash) |
| `relay_api_secret` | Same value as `RELAY_API_SECRET` in the relay's `.env` |

Leave `callback_token` and `encoding_aes_key` empty — `relay_url` takes priority when set.

After saving, use **Test Connection** to confirm the relay is reachable. The output will show `wecom-ask mode: relay` and `Relay URL: https://... [OK]`.

## Security notes

- Always run behind HTTPS; WeCom requires it for callback URLs.
- Set `RELAY_API_SECRET` in production. Without it, any client that knows a `task_id` can read or delete responses.
- Responses are stored in memory only — a container restart clears all pending responses.
