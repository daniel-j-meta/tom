# Tom

A small home server for OpenClaw assistants, designed for **Ubuntu Server with 8 GB RAM**.
People open a normal HTTPS app and sign in through Cloudflare Access. Each assistant has
its own memory, browser profile, and credentials. One assistant runs at a time by default.

## Install

Use a dedicated Ubuntu Server **24.04 or 26.04** machine, with at least 8 GB RAM,
20 GB free disk for initial images, and a domain whose DNS is managed by Cloudflare.
The guest range `172.30.0.0/16` must be unused by your LAN, VPN, and other Docker applications;
setup checks before adding its narrow host rule.
Both amd64 and arm64 use the upstream multi-platform OpenClaw image.

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/daniel-j-meta/tom.git
cd tom
sudo ./setup.sh
```

The interactive setup asks for your app hostname, your email, invited emails, Cloudflare
account/zone IDs, a Cloudflare API token, and an OpenAI API key. Secret inputs are hidden.
It installs Docker, builds images, configures Cloudflare Access and Tunnel, publishes DNS,
creates an assistant for each invited user, and installs systemd startup services.
It then verifies the installed Cloudflare resources, public HTTPS/Access login challenge,
the real browser's internet access and control handoff, and one small live model reply.
The model check uses API credits. Setup reports success only after these checks pass.
On failure, fix the reported issue and rerun `sudo tom verify`; installation remains available.
For an intentional installation without live checks, use `--skip-live-checks`; setup clearly
reports that verification was skipped.

### Cloudflare prerequisites

1. Create a Cloudflare Zero Trust organization. Enable a login method, such as One-time PIN.
2. Choose an unused hostname, such as `tom.example.com`.
3. Create a scoped API token with **Account / Cloudflare Tunnel / Edit**,
   **Account / Access: Apps and Policies / Edit**, **Account / Access: Organizations / Read**,
   and **Zone / DNS / Edit**, for only your account and DNS zone.
4. Copy the account ID and zone ID from the Cloudflare dashboard.

Setup refuses to overwrite an existing DNS record or an Access app it did not create.
If a Cloudflare call fails, it saves the IDs already created so rerunning can resume.
Access is configured before the DNS record is published. The origin also verifies
Cloudflare's JWT signature, audience, issuer, expiry, and invited email independently.
An email header alone never grants access.

Cloudflare API credentials are used only during setup and are not retained. The tunnel
token is stored outside the checkout, in `/opt/tom/secrets`, and mounted as a read-only file.

## Use

Open your chosen HTTPS hostname. After sign-in, select your assistant and choose **Start**.
The first start may take up to 90 seconds. Send a message to add it to the durable queue.
Messages wait while another assistant is using the active slot.

The app includes chat history, a live browser view, browser tabs, memory viewing, and
encrypted credential forms. It renders model output as text rather than executing HTML.
**Full OpenClaw interface** opens the upstream interface for approval cards, input questions,
and richer native features. Its short-lived pairing link stays in the URL fragment, and
every HTTP/WebSocket request still passes the portal's signed identity and instance-owner
checks. Keeping that interface connected keeps its active instance warm.

### Browser control

- **View only:** watch the browser while the assistant works.
- **Take browser control:** abort the foreground turn and freeze the entire gateway
  container, including native Codex children. The separate browser stays running.
- Click, scroll, type, paste, and complete MFA in the browser view.
- **Give back to assistant:** resume the gateway. Send another message to continue work;
  interrupted jobs are not automatically submitted again.
- Human control expires after 15 minutes. Expiry stops the instance instead of resuming
  automation without you. Idle assistants stop after three minutes to reclaim RAM.

Saved website passwords can be filled only while you hold browser control, on the exact
saved HTTPS hostname. Filling verifies the page origin and inputs together and does not
submit the form. For unfamiliar sites, manual login and MFA are the simplest approach.
Password filling currently asks for the username/password CSS input selectors.

## Manage the server

```bash
sudo tom status                     # Full instance IDs, owners, and states
sudo tom start INSTANCE_ID
sudo tom stop INSTANCE_ID
sudo tom logs                       # Management and tunnel logs
sudo tom logs INSTANCE_ID           # Gateway logs
sudo tom doctor                     # Authenticated local health checks
sudo tom doctor --live              # Wait for a small real model check; uses API credits
sudo tom verify                     # Repeat public Access, browser, handoff, and live model checks
sudo tom down                       # Stop instances and services
sudo tom up
```

Local administration uses a root-protected Unix socket. No admin API token is accepted
over the public TCP listener. Docker and browser debugging ports are not published.
Only the web app binds a host port, and that port binds to `127.0.0.1`.

### Rerun and update

Rerunning `sudo ./setup.sh` retains the existing configuration and credentials.
To change the hostname, invited users, or setup credentials, run:

```bash
sudo ./setup.sh --reconfigure
```

New invited users can receive assistants through the administrator's **+** button.
Updating code and rerunning setup rebuilds the management image and restarts services.
The upstream OpenClaw image is pinned by digest. Changing that pin is an explicit upgrade;
back up first and repeat runtime verification. One gateway owns each state directory.

## Storage and backups

Runtime data lives in `/opt/tom/data`, separate from the Git checkout. Each instance has
its own OpenClaw state/workspace, Codex state, and Chromium profile. API keys and saved
passwords are authenticated AES-256-GCM ciphertext in the management database.
The vault master key is root-protected at `/opt/tom/secrets/vault.key`; guests never mount it.
Short-lived broker capabilities live in `/run/tom`, which Ubuntu keeps in memory.

Use an **age** recipient with its private key stored separately from the server:

```bash
age-keygen -o recovery.key
# Store recovery.key offline; use the printed public recipient below.
sudo tom backup --recipient age1YOUR_PUBLIC_RECIPIENT --output /media/backup/tom.age
```

Backup stops active instances and briefly stops the management writer for consistent
SQLite/browser data, then encrypts the archive. It includes the vault recovery key and
Cloudflare tokens inside the encrypted archive. Assistants remain stopped after backup.

Restore into an empty installation only:

```bash
sudo ./setup.sh --restore /media/backup/tom.age --identity /media/recovery.key
```

The 256 GB SSD is sufficient to start, but browser profiles and downloads can grow.
Container logs rotate. Keep backups off the server, watch `df -h`, and remove unneeded
downloads through the website/assistant before storage fills.

## Isolation and limits

- One active assistant by default: a 2 GB gateway and 1.5 GB browser, plus small management
  and tunnel services. Additional saved assistants consume disk rather than running RAM.
- Separate internal Docker networks for each instance. Guests have no direct internet
  route. An authenticated CONNECT proxy allows public HTTPS destinations on port 443.
- DNS results are checked and the approved literal IP is dialled, preventing a second
  lookup from redirecting the connection into a private network. Private IPv4/IPv6,
  loopback, link-local, CGNAT, and reserved destinations are blocked. A host INPUT rule
  blocks guest access to host bridge services.
- Guests run as UID 1000, without host capabilities or the Docker socket. Scoped seccomp
  and AppArmor profiles support Chromium/Codex's inner namespaces. Chromium sandboxing is
  explicitly enabled and startup fails if it cannot run.
- Codex uses the official runtime with guardian review. A read-only requirements file
  restricts approvals and sandbox modes; its configuration cannot be rewritten by the agent.
- Scheduled autonomous work and heartbeats are disabled in this first release. The portal
  owns the queue and active-instance limit. Management restarts stop guests and mark unknown
  running jobs interrupted, instead of replaying possible side effects.

These are containers sharing one kernel, not mutually adversarial-user VMs. The management
service is trusted and has Docker's host-management authority. Keep it and the server patched.
The small server is suitable for invited users; it is not a public anonymous hosting service.

The vault master key lives on the same host to permit unattended boot. Root access or physical
disk theft can compromise it: use full-disk encryption when installing Ubuntu if that threat
matters. Browser login cookies and OpenClaw/Codex session files are sensitive and are not all
encrypted individually. A signed-in browser can exercise account privileges without knowing
the password. Protected API keys are resolved into the trusted gateway runtime and are not
a guarantee against compromise of that runtime.

Luna inference runs at OpenAI; page content sent to the model leaves your home server.
`gpt-6-luna` is the configurable default, and your account must actually have access.
No model call is silently substituted with a different model.
Guardian review covers eligible approval requests, not every already-permitted browser
action. Keep consequential writes under human supervision.

Cloudflare terminates HTTPS at its edge. Check its public-route streaming terms before
using sustained browser streaming; the viewer uses JPEG frames over WebSockets, not a
separate video service. This package does not promise that a free Cloudflare plan covers it.

## Development and tests

```bash
uv sync --extra test
uv run pytest
uv run ruff check tom tests
shellcheck setup.sh
docker build -t tom-openclaw:2026.10.7 -f containers/Dockerfile .
```

Unit/integration tests cover signed Cloudflare identity, cross-user access, CSRF, encrypted
credentials, secret binding, private-address blocking, submission replay, memory symlink
escape, and Cloudflare setup ordering/idempotency. See `docs/VERIFICATION.md` for the actual
checks performed on this revision and the checks that require your Ubuntu/Cloudflare account.

## References

- [OpenClaw Docker deployment](https://docs.openclaw.ai/install/docker)
- [Codex plugin approval and sandbox modes](https://docs.openclaw.ai/plugins/codex-harness-reference/approval-and-sandbox)
- [OpenClaw secret resolver contract](https://docs.openclaw.ai/gateway/secrets/secretref-contract)
- [OpenAI automatic review](https://developers.openai.com/codex/sandboxing/auto-review)
- [Cloudflare JWT validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/)
- [Cloudflare Tunnel WebSocket and streaming guidance](https://developers.cloudflare.com/cloudflare-one/faq/cloudflare-tunnels-faq/)
