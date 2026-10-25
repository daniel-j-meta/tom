# Third-party software

- OpenClaw: https://github.com/openclaw/openclaw — MIT. The pinned upstream image
  includes its own notices, Chromium notices, and dependencies; these remain in the image.
- OpenAI Codex: https://github.com/openai/codex — Apache-2.0. Distributed inside the
  upstream OpenClaw Codex plugin; preserve the upstream image's notices.
- Moby default seccomp profile: https://github.com/moby/profiles — Apache-2.0.
  `security/seccomp.json` is derived from that profile with namespace-related syscall
  changes described in `security/README.md`. See `security/APACHE-2.0.txt`.
- Cloudflared: https://github.com/cloudflare/cloudflared — Apache-2.0.
  Run from the official Cloudflare image.

This repository's MIT license does not replace licenses of included or downloaded
components. Python packages and container distributions retain their own license files.
