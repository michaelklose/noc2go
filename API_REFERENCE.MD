# NOC2GO API (v1) – Developer Documentation

> **Base URL:** `https://<host>:<port>` (default port `8443`; see `server.port` in `noc2go.yaml`)
> All routes are served over **HTTPS**. A self‑signed certificate is generated on first start.

---

## 1 · Authentication & Session

| Step                | Endpoint  | Method                | Form Fields                                                       | Success Response                                                                   |
| ------------------- | --------- | --------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Log in**          | `/login`  | `POST`                | `user` – username<br>`pass` – password                            | HTTP `303 See Other` → `/`<br>Sets secure, HTTP‑only cookie `noc2go` (8 h expiry). |
| **Log out**         | `/logout` | `POST` or `GET`       | –                                                                 | HTTP `303 See Other` → `/login`<br>Deletes cookie `noc2go`.                        |
| **Change password** | `/passwd` | `GET` (form) / `POST` | `cur` – current password<br>`new1`, `new2` – new password (twice) | On success: redirects to `/logout`, forcing re‑login.                              |

All other endpoints are protected by the `authMiddleware`; the browser must present the **`noc2go`** cookie.

---

## 2 · HTML Pages (for human operators)

| Path        | Method | Purpose                                                             |
| ----------- | ------ | ------------------------------------------------------------------- |
| `/`         | `GET`  | Dashboard (basic host info + navigation).                           |
| `/info`     | `GET`  | Detailed system information (kernel, uptime, routes, DNS, proxies). |
| `/dns`      | `GET`  | DNS‑lookup tool (AJAX → `/api/dns`).                                |
| `/ping`     | `GET`  | Streamed ping utility (AJAX + SSE → `/api/ping`).                   |
| `/settings` | `GET`  | Manage custom DNS servers, saved ping targets and account.          |

*(These pages embed JavaScript that calls the JSON/SSE APIs documented below.)*

---

## 3 · JSON & Streaming APIs

### 3.1 DNS lookup `GET /api/dns`

| Query Parameter | Required | Example                                      | Notes                                                             |
| --------------- | -------- | -------------------------------------------- | ----------------------------------------------------------------- |
| `name`          | ✔        | `example.com` / `8.8.8.8`                    | For `PTR`, an IP or reverse‑ARPA name.                            |
| `type`          | ✔        | `A`, `AAAA`, `MX`, `NS`, `PTR`, `TXT`, `SRV` | Unsupported → `error`.                                            |
| `server`        | ✘        | `1.1.1.1:53` / `system`                      | Defaults to first resolver in `/etc/resolv.conf` or `8.8.8.8:53`. |

<details>
<summary>Successful response</summary>

```jsonc
{
  "server": "1.1.1.1:53",
  "records": [
    // structure depends on record type:
    // A / AAAA      → { "address": "203.0.113.5" }
    // MX            → { "host": "mail.example.com.", "priority": 10 }
    // NS / PTR      → { "host": "ns1.example.com." }
    // TXT           → { "text": "v=spf1 include:..." }
    // SRV           → { "target": "sip.example.com.", "port": 5060,
    //                   "priority": 0, "weight": 5 }
  ]
}
```

If resolution fails: `{"error":"NXDOMAIN"}` or an explanatory message.

</details>

---

### 3.2 Ping (stream) `GET /api/ping`

**Server‑Sent Events** (MIME `text/event-stream`).

| Query Parameter | Default | Description                                    |
| --------------- | ------- | ---------------------------------------------- |
| `target`        | –       | Hostname or IP to ping (resolved server‑side). |
| `family`        | `auto`  | `auto`, `ipv4`, `ipv6`.                        |
| `count`         | `5`     | Number of echoes (`ping -c/-n`).               |
| `size`          | `64`    | Payload bytes (`ping -s/-l`).                  |
| `interval`      | `1`     | Seconds between packets (`ping -i`).           |
| `ttl`           | `64`    | Time‑to‑live / hop limit.                      |
| `df`            | `false` | `true`→ don’t‑fragment (Linux only).           |

**Event stream**

| Event     | Payload (JSON)                                                                                | Notes                     |
| --------- | --------------------------------------------------------------------------------------------- | ------------------------- |
| `reply`   | `{ "seq":1,"ip":"203.0.113.5","ttl":62,"time":0.648,"timestamp":"2025‑05‑04T09:01:23.456Z" }` | One per received echo.    |
| `summary` | `{ "sent":5,"recv":5,"loss":0,"min":0.63,"avg":0.71,"max":0.85 }`                             | Sent after process exits. |

Errors close the stream and return `502`/`500`.

---

### 3.3 Settings – Custom DNS Servers

| Endpoint                   | Method | Body (JSON)                    | Success response                                      |
| -------------------------- | ------ | ------------------------------ | ----------------------------------------------------- |
| `/api/settings/dns/add`    | `POST` | `{ "server": "1.1.1.1[:53]" }` | `{ "success": true, "servers": ["1.1.1.1:53", …] }`   |
| `/api/settings/dns/remove` | `POST` | `{ "server": "1.1.1.1[:53]" }` | same structure; `success:false` + `error` on failure. |

Servers are normalised to `host:53` if no port specified.

---

### 3.4 Settings – Saved Ping Targets

| Endpoint                    | Method | Body (JSON)                   | Success response                                      |
| --------------------------- | ------ | ----------------------------- | ----------------------------------------------------- |
| `/api/settings/ping/add`    | `POST` | `{ "target": "example.com" }` | `{ "success": true, "targets": ["example.com", …] }`  |
| `/api/settings/ping/remove` | `POST` | `{ "target": "example.com" }` | same structure; `success:false` + `error` on failure. |

---

## 4 · Configuration (`noc2go.yaml`)

```yaml
server:
  port: 8443          # HTTPS listener
  https_key: noc2go.pem  # certificate file

auth:
  users:
    - name: admin
      role: admin      # "admin" or "user" (future use)
      pw_hash: "$2a$..."  # bcrypt hash
      pw_oneuse: false    # optional, force change on first login
      expires: "2025-12-31T23:59:59Z"  # optional RFC‑3339 expiry

tools:
  allow_privileged: false   # enable raw‑socket functions (root)

dns:
  custom_servers:           # optional list displayed in UI
    - "1.1.1.1:53"
    - "9.9.9.9:53"

ping:
  targets:                  # saved targets shown in /ping
    - "example.com"
    - "8.8.8.8"
```

Edit the file manually **or** use `/settings` UI/JSON endpoints.

---

## 5 · Error Handling

* All JSON APIs return `{"error":"<message>"}` with HTTP status `200` for logical errors (duplicate, NXDOMAIN, …)
  Low‑level failures use appropriate HTTP codes (`400` bad input, `405` method not allowed, `500` internal).
