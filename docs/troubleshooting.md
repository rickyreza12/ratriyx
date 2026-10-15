# Troubleshooting (detailed)

Use the observation, not the guess. Run `ratriyx doctor --mode tor --json` to get the raw check list.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `run`, the child's own code is passed through. |
| 1 | A check or operation failed. Nothing was launched. |
| 2 | Usage or config error. |
| 3 | Unsupported platform (unknown operating system). |
| 4 | Tor mode refused to launch because the route is not verified, or an interop launcher was refused. |
| 5 | An action needs `--yes` after review. Nothing changed. |
| 70 | Ratriyx lost track of a running child. The message starts with `ratriyx:`. |
| 128+N | The child stopped on signal N. |

When `run` exits with a code, a code from 2 to 5 can also come from the child itself. Read the `ratriyx:` prefix on stderr to tell them apart.

## Symptoms

### `FAIL tor.instance: Tor instance not running`

Tor is stopped, or only the master `tor` unit is active. `tor` can show `active (exited)` while the instance is down. Ratriyx checks `tor@default` first, then plain `tor`.

```bash
systemctl status tor@default
sudo systemctl start tor@default        # or: ratriyx service start tor --yes
```

```bash
systemctl status tor@default
sudo systemctl start tor@default        # or: ratriyx service start tor --yes
```

### `FAIL listener.8118` or `listener.9050`: nothing listening

The service that should own the port is not running. Start it, or check its configuration. Ratriyx does not kill a process by its port number.

### `FAIL privoxy.forwarding: rule missing`

Privoxy does not forward to Tor. Preview, then apply with approval:

```bash
ratriyx configure --dry-run
sudo ratriyx configure --yes
```

### `FAIL privoxy.forwarding: rules at lines ... route destinations directly`

A rule sends traffic direct, or catches all traffic outside Tor. Ratriyx refuses to change it, because the right fix depends on your setup. Edit those lines by hand, then re-run `ratriyx doctor`.

### `FAIL tor.istor: connection refused`

Privoxy is not listening on the proxy port. Check `listener.8118` and `systemctl status privoxy`.

### `FAIL tor.istor: IsTor false`

The request reached the internet without going through Tor. Check the forwarding rule and that Privoxy was restarted after the rule was added.

### `FAIL tor.istor: empty reply` or `SSL_ERROR_SYSCALL` right after a start

Tor is still building circuits. Wait for `Bootstrapped 100%` in `journalctl -u tor@default`, then run the check again. Ratriyx does not retry in a loop.

### `FAIL tor.istor: HTTP 407`

Privoxy wants proxy authentication. Ratriyx does not send credentials. Check Privoxy's `actionsfile` and `user.action` rules.

### `WARN env.proxy: proxy variables set in this process`

Your shell has proxy variables. Direct mode removes them for children, but applications that read them directly are not affected. Clear them with `eval "$(ratriyx off)"`.

### `WARN opencode.resolution: Windows interop launcher`

`opencode` on your PATH is a Windows program started through WSL. Its environment comes from `WSLENV`, which Ratriyx cannot verify. Tor mode refuses it. Direct mode runs it and labels the environment "not verified".

### `run` refuses: "Tor route not verified"

Nothing was launched. Fix the failing check from `doctor --mode tor`. The only way to run anyway is `--allow-unverified`, which labels the route unverified in every output.

### `FAIL direct.https` in direct mode

Your general network connection is down, or DNS fails. Ratriyx cannot fix that. Check the connection first.

### A provider says "Rate limit exceeded" or HTTP 429

This is a provider limit. It is not a proxy or Tor fault, and changing the Tor exit does not change it. Check your quota, plan, and key status with the provider. Ratriyx does not rotate identities or retry in a loop.

### `rotate` says "cooldown" or does not change the exit

`rotate` sends one NEWNYM signal per 10 seconds at most. The exit can stay the same, and circuits in use keep working. Run `ratriyx ip` afterwards to see the result.

### `ratriyx: unsupported platform` (exit 3)

Ratriyx supports Linux, native Windows, and macOS. WSL1, untested setups, and unknown systems are labelled conditional or refused. On native Windows, run the Windows build in Windows PowerShell with the scripts in `scripts/windows/`.

## Collecting a report

```bash
ratriyx doctor --mode tor --json > doctor.json
```

The output redacts URL passwords and token-like values. Still check the file before you share it.
