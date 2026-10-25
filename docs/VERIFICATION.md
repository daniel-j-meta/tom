# Verification

Checked October 25, 2026. This is an initial setup package for invited users.

## Passed

- 36 automated tests: signed JWT validation, wrong issuer/audience/expiry, forged signatures,
  invited-user checks, cross-user instance access, CSRF, encrypted secret storage and binding,
  private IPv4/IPv6 blocking, scoped DNS, duplicate submission handling, restart recovery,
  memory symlink escape, Cloudflare setup ordering/idempotency, and staged restore.
- Ruff, JavaScript syntax checks, ShellCheck, and Docker Compose validation.
- Management and shared OpenClaw/browser Docker images built successfully.
- Generated OpenClaw config validated by the pinned upstream image without warnings.
- Chromium launched with its sandbox enabled, non-root execution, dropped capabilities,
  no-new-privileges, and the package's scoped seccomp policy.
- Codex ran `/bin/echo CODEX_SANDBOX_OK` with its `:workspace` sandbox profile inside a
  disposable container using the package's seccomp policy, without a model request.
- Actual Docker integration: management startup, gateway/browser startup, real gateway
  handshake, chat history, approval lookup, full-gateway pause on takeover, continued
  browser operation, JPEG streaming, input, resume, memory after stop/restart,
  upstream Control UI HTML, and the short-lived pairing URL.
- Browser UI preview: sign-in, assistant creation/selection, memory dialog, encrypted website
  credential submission, and no browser JavaScript errors. The preview does not run agents.

## Requires the target server/account

- This environment resolves public domains to reserved test IPv6 addresses. The mandatory
  public-address check correctly rejected them. Successful public HTTPS browsing and real
  provider connectivity remain to be checked with normal public DNS on the Ubuntu server.
  The security policy was not loosened to make this test pass.
- Docker integration uses fake API credentials. No authenticated inference, actual Luna
  account access, model quality, or automatic-review decisions were evaluated. Run
  `sudo tom doctor --live` after setup; it waits for a small real model request.
- No Cloudflare credentials were provided here. Live creation of Access policies, DNS, and
  a tunnel was not performed. Those requests are tested with a fake API and executed by
  the target server's wizard with your scoped token.
- This host has no AppArmor support. Ubuntu setup installs the scoped profile and runs its
  Chromium launch gate there. No host-wide security settings were installed here.
- Full Ubuntu installation/reboot and recovery with a real age key were not performed here.
  Shell syntax, configuration, staged restore checks, and Docker lifecycle were verified.
- The native UI's full interactive approval flow was not exercised with a real model
  request; its page, proxy route, and pairing link were checked against the real gateway.

## Repeat

```bash
uv sync --extra test
uv run pytest -q
uv run ruff check tom tests scripts
shellcheck setup.sh
docker compose -f compose.yaml config --quiet
docker build -t tom-openclaw:2026.10.7 -f containers/Dockerfile .
docker build -t tom-app:0.1.0 .
uv run python scripts/integration.py
```

Integration uses temporary directories and containers, changes no Cloudflare resources,
and cleans up only fixtures whose mounts point to its unique temporary root.
