# Guest process permissions

`seccomp.json` starts from the public Moby default profile at
https://github.com/moby/profiles/blob/main/seccomp/default.json
(upstream bytes SHA256 `6416b47770785a41ac59073cdc77d9fe98517df2799dc83ef207e622de3053f6`).
It permits `clone`, `clone3`, `setns`, `unshare`, `chroot`, `mount`, `umount2`, and
`pivot_root` so Chromium and Codex can create their inner user/mount namespaces.
The parent container receives no capabilities; privileged operations there remain
refused by the kernel. Other default syscall restrictions remain.
The upstream profile is Apache-2.0 licensed; see THIRD_PARTY_NOTICES.md.

Guests run as UID 1000, with all capabilities dropped, no-new-privileges, their own
PID/network namespaces, and an isolated internal network. Ubuntu setup installs
the scoped AppArmor profile rather than disabling user namespace restrictions
globally. Browser startup explicitly enables Chromium's sandbox and fails if it
cannot start; it never falls back to `--no-sandbox`.

The management service is trusted and has the Docker socket. Guest containers do
not receive that socket, the vault master key, or another instance's files.
