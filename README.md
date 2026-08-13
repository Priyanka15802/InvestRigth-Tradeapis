# HDFC IR Order + LTP Tool

A minimal local tool for the HDFC Securities InvestRight (IR) Open API: a
Flask backend that owns the 6-step login flow and a single `index.html`
frontend for logging in, watching LTP, and placing/modifying/cancelling
orders.

**This places real orders once "DRY RUN" is switched off. Read the Safety
section before you touch that toggle.**

## How the login flow works

The IR API login is a 6-step sequence. The backend runs it as a stateful
session (in memory only, never written to disk):

| Step | Call | Carries forward |
|---|---|---|
| 1 | `GET /login?api_key=...` | response `tokenId` -> used as `token_id` in steps 2-5 |
| 2 | `POST /login/validate?api_key=...&token_id=...` `{username, password}` | triggers OTP; no new id |
| 3 | `POST /twofa/validate?api_key=...&token_id=...` `{answer: otp}` | response `requestToken` -> used in steps 5-6 |
| 4 | `GET /twofa/resend?api_key=...&token_id=...` | resend OTP, on demand |
| 5 | `GET /authorise?api_key=...&token_id=...&consent=...&request_token=...` | if the response includes its own request token field, that value is used for step 6 instead; otherwise step 3's token is reused |
| 6 | `POST /access-token?api_key=...&request_token=...` `{apiSecret}` | response `accessToken` -> stored for all trading calls |

**`HDFC_CONSENT` must be the lowercase string `true`.** This was found by
live testing: any other value (`Y`, `True`, etc.) still lets Step 5
succeed, but silently leaves the session unauthorised on HDFC's side, and
Step 6 then fails with `{"error": "authorization not provided"}` even
though Step 6's own request is unchanged. `.env.example` already defaults
to the correct value — don't override it.

## Project layout

```
app.py              Flask backend (auth + trading proxy)
index.html           Frontend, served at "/" by the backend
requirements.txt     Python dependencies
.env.example          Template for required secrets
```

## Install & run (local)

```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and fill in HDFC_API_KEY, HDFC_API_SECRET, HDFC_USERNAME, HDFC_PASSWORD

python app.py
```

Open `http://localhost:5000`.

1. Click **Start Login** (runs steps 1-2, sends you an OTP).
2. Enter the OTP and click **Submit OTP** (runs steps 3, 5, 6). Use
   **Resend OTP** if it doesn't arrive.
3. Once logged in, the LTP and Order panels appear.

## Safety

- **DRY RUN** is on by default and applies only to order placement,
  modification, and cancellation (never to login). While on, the backend
  builds the exact request it would send to HDFC — method, URL, headers,
  body — logs it to the server console (with the API key and access token
  masked), and returns a mock success with a synthetic `DRYRUN-...` order
  id. No live order call is made.
- Turning DRY RUN off shows a browser confirm dialog before **Place** and
  before **Cancel**.
- Test with DRY RUN on until you've verified the request shapes in the
  server log look correct for your account.

## Secrets handling

- All secrets (`HDFC_API_KEY`, `HDFC_API_SECRET`, `HDFC_USERNAME`,
  `HDFC_PASSWORD`) live only in `.env`, read once at startup by the
  backend. The browser never sees them.
- The login session (`tokenId`, `requestToken`, `accessToken`) is held in
  an in-memory Python dict and is lost on restart — it is never written
  to disk or logged.
- Server logs never print the API key, API secret, password, OTP, or
  access token. Any error text coming back from a failed HTTP request is
  passed through a `redact()` step that strips those known secret values
  before it's logged or returned to the browser.
- `.env` is listed in `.gitignore` — never commit it.

## Notes on the LTP endpoint

HDFC's `fetch-ltp` call takes an **exchange + numeric security token**
pair (e.g. `NSE` / `21840`), not a trading symbol string, and is called
with `PUT`. `GET /api/ltp?exchange=NSE&token=21840` on this backend wraps
that into the batch body HDFC expects. The frontend's "Get LTP" fetches a
single pair; auto-refresh re-polls it every 5 seconds while the checkbox
is on.

## Deploying on a small cloud VM (static IP)

These steps assume a plain Ubuntu/Debian VM with Python 3.10+.

### Option A: systemd

```bash
sudo mkdir -p /opt/hdfc-ir-tool
sudo chown $USER:$USER /opt/hdfc-ir-tool
# copy app.py, index.html, requirements.txt, .env.example into /opt/hdfc-ir-tool
cd /opt/hdfc-ir-tool
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp .env.example .env
# edit .env with real values; chmod 600 .env
chmod 600 .env
```

Install `gunicorn` for a production WSGI server:

```bash
.venv/bin/pip install gunicorn
```

Create `/etc/systemd/system/hdfc-ir-tool.service`:

```ini
[Unit]
Description=HDFC IR Order + LTP Tool
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/hdfc-ir-tool
EnvironmentFile=/opt/hdfc-ir-tool/.env
ExecStart=/opt/hdfc-ir-tool/.venv/bin/gunicorn -w 1 -b 127.0.0.1:5000 app:app
Restart=on-failure
User=YOUR_LINUX_USER

[Install]
WantedBy=multi-user.target
```

`-w 1` (a single worker) matters here: the login session lives in that
one process's memory, so multiple workers would each have their own
(inconsistent) session state.

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now hdfc-ir-tool
sudo systemctl status hdfc-ir-tool
```

Put nginx (or another reverse proxy) in front of `127.0.0.1:5000` for
TLS/port 80/443 if you want to reach it over HTTPS from outside the VM.

### Option B: pm2

pm2 is a Node process manager but works fine for keeping a Python process
alive too:

```bash
npm install -g pm2
cd /opt/hdfc-ir-tool
pm2 start ".venv/bin/gunicorn" --name hdfc-ir-tool -- -w 1 -b 127.0.0.1:5000 app:app
pm2 save
pm2 startup   # follow the printed instructions to enable on boot
```

Either way: keep this tool bound to `127.0.0.1` and reverse-proxy it, or
otherwise firewall it, since a logged-in session can place live orders —
don't expose port 5000 directly to the internet.
