# FreeBSD how-to

This guide installs `qobuzconnect2mpd` as a FreeBSD `rc.d` service.

## Install dependencies

Install the build tools, libraries, and MPD:

```sh
pkg install meson ninja pkgconf curl libmicrohttpd jsoncpp libmpdclient openssl musicpd
```

If you build from ports instead of packages, install the equivalent ports for
the same libraries.  The build uses `pkg-config` metadata, so `pkgconf` must be
available.

## Build

From the source tree:

```sh
meson setup build -Dinit_system=freebsd --prefix=/usr/local
ninja -C build
meson test -C build --print-errorlogs
```

`-Dinit_system=freebsd` forces FreeBSD `rc.d` support.  On a native FreeBSD
host, `-Dinit_system=auto` also selects it automatically:

```sh
meson setup build --prefix=/usr/local
```

Use `-Dinit_system=none` if you want only the binary.

## Install

Install as root:

```sh
ninja -C build install
```

This installs:

| File | Purpose |
|------|---------|
| `/usr/local/bin/qobuzconnect2mpd` | daemon executable |
| `/usr/local/etc/rc.d/qobuzconnect2mpd` | FreeBSD service script |
| `/usr/local/etc/qobuzconnect2mpd.conf.sample` | sample daemon configuration |

If you use a different `--prefix`, the installed binary, service script, and
sample configuration follow that prefix. Meson does not install or overwrite a
live configuration. The service defaults to `/usr/local/etc/qobuzconnect2mpd.conf`.

On a direct FreeBSD install, Meson also creates the unprivileged
`qobuzconnect2mpd` user and group, then creates `/var/db/qobuzconnect2mpd`
owned by that account with mode `0700`. This setup is skipped when installing
into `DESTDIR`, so package builds can stage files without mutating the build
host.

## Configure MPD

Install and enable MPD first:

```sh
sysrc musicpd_enable=YES
service musicpd start
```

Make sure MPD listens where `qobuzconnect2mpd` will connect.  The default
`qobuzconnect2mpd` settings expect TCP on localhost port 6600:

```conf
bind_to_address "127.0.0.1"
port "6600"
```

Restart MPD after changing its configuration:

```sh
service musicpd restart
```

## Configure qobuzconnect2mpd

Create and edit the live configuration from the installed sample:

```sh
cp /usr/local/etc/qobuzconnect2mpd.conf.sample /usr/local/etc/qobuzconnect2mpd.conf
ee /usr/local/etc/qobuzconnect2mpd.conf
```

At minimum, check:

```conf
qconnectfriendlyname = FreeBSD MPD
mpdhost = localhost
mpdport = 6600
qconnectformatid = 27
```

Authentication is OAuth-only. Point the daemon's state directory at the service
account's home; the OAuth token (`user_token`) and device UUID (`device.uuid`)
are stored there:

```conf
qconnectstatedir = /var/db/qobuzconnect2mpd
```

The daemon first uses `/session/start` and `/file/url`; segmented CMAF/FLAC
responses are reconstructed for MusicPD. Direct `/file/url` responses and the
classic `track/getFileUrl` endpoint are compatibility fallbacks. No Qobuz
username or password belongs in the configuration; the account is linked once
through a browser, as described in
[First authentication with Qobuz](#first-authentication-with-qobuz).

## Service account

The installed `rc.d` script defaults to the unprivileged `qobuzconnect2mpd`
account and `/var/db/qobuzconnect2mpd` as its home. A direct `ninja install`
creates them automatically. If you installed into `DESTDIR` or are assembling a
package manually, create them on the target system:

```sh
pw groupadd qobuzconnect2mpd
pw useradd qobuzconnect2mpd -d /var/db/qobuzconnect2mpd -s /usr/sbin/nologin
install -d -o qobuzconnect2mpd -g qobuzconnect2mpd -m 700 /var/db/qobuzconnect2mpd
chown root:qobuzconnect2mpd /usr/local/etc/qobuzconnect2mpd.conf
chmod 640 /usr/local/etc/qobuzconnect2mpd.conf
```

Use mode `600` and owner `qobuzconnect2mpd:qobuzconnect2mpd` instead if the
configuration contains secrets that only the daemon should read.

See [First authentication with Qobuz](#first-authentication-with-qobuz) for the
one-time interactive login that populates this account's token cache.

## First authentication with Qobuz

Authentication is a one-time interactive browser login. The token is then cached
and reused on every later start, so the service runs unattended afterwards.

The token must be written by the account that will run the service — the
unprivileged `qobuzconnect2mpd` user. So the first login is performed by running
the daemon once, in the foreground, as that account, in `-L` bootstrap mode: `-L`
completes the login, writes the token, and exits on its own.

No browser runs as the service account. The daemon prints a login URL, you open
it in any browser that can reach the daemon host, and the daemon itself receives
the callback and writes the token.

### Before you start

The token is written to `<qconnectstatedir>/user_token`, so make sure
`/usr/local/etc/qobuzconnect2mpd.conf` points the state directory at the service
account's home (see [Configure qobuzconnect2mpd](#configure-qobuzconnect2mpd)):

```conf
qconnectstatedir = /var/db/qobuzconnect2mpd
```

Stop the service if it is already running — a second instance cannot bind
`qconnectport`:

```sh
service qobuzconnect2mpd stop
```

### Run the daemon once as the service account

The account has `/usr/sbin/nologin` as its shell, so `su - qobuzconnect2mpd`
fails with `This account is currently not available.`

If `security/sudo` is installed, use it — it execs the binary directly and does
not care about the account's shell:

```sh
sudo -u qobuzconnect2mpd /usr/local/bin/qobuzconnect2mpd \
  -c /usr/local/etc/qobuzconnect2mpd.conf -L
```

No `HOME` needs to be set: the daemon takes its state directory from
`qconnectstatedir` in the config (set above). The `qobuzconnect2mpd` account is
`nologin` and has no desktop home, so the daemon does not derive a state path
from a home at all — if `qconnectstatedir` were unset it would abort and ask you
to set it, rather than inventing `~/.local/state` under the account.

With base-system `su` only, give the account a shell for the duration and put it
back afterwards. Quote the command passed to `su -c` so the daemon receives its
own `-c` argument:

```sh
pw usermod qobuzconnect2mpd -s /bin/sh
su -m qobuzconnect2mpd -c \
  '/usr/local/bin/qobuzconnect2mpd -c /usr/local/etc/qobuzconnect2mpd.conf -L'
pw usermod qobuzconnect2mpd -s /usr/sbin/nologin
service qobuzconnect2mpd start
```

Do not add `-d` to this run. The login URL is written to stdout only — it never
goes to `qconnectlogfile` — and daemonising sends stdout to `/dev/null`, losing
the URL.

### Complete the login in a browser

The daemon prints:

```
  Not authenticated — open this URL in a browser to log in:

  https://www.qobuz.com/signin/oauth?...

  (after login this device will connect automatically)
```

Open that URL and log in with your Qobuz account. The redirect target is built
from the host's LAN address — for example
`http://192.168.1.20:9093/oauth/callback/<nonce>` — so the browser can be on any
machine on the same network, not necessarily the FreeBSD host. If `pf` or
another firewall is active, `qconnectport` must be reachable from the browser.

With `-L` the daemon exits by itself once the token is written, right after the
confirmation page is returned; without `-L`, stop the foreground daemon with
Ctrl-C after the page appears. Either way the token is persisted first.

### Verify and start the service

```sh
ls -l /var/db/qobuzconnect2mpd/user_token
```

Expect mode `-rw-------` and owner `qobuzconnect2mpd`. Then:

```sh
service qobuzconnect2mpd start
```

If the service ever starts without a cached token it exits immediately with an
error pointing back at this `-L` bootstrap, rather than running silently unable
to stream.

### If the URL expires or the login fails

The callback path carries a random nonce, accepts exactly one exchange, and
expires after five minutes. Start the daemon again to generate a fresh URL.

You can also skip the foreground run entirely: start the service normally and
read the same first-run URL from syslog, normally `/var/log/messages` — the rc
script runs the daemon under `daemon -S`, which forwards stdout there. Restart
the service to generate a new URL if that one expires.

If no URL is printed, the daemon already has a valid cached token. Remove
`/var/db/qobuzconnect2mpd/user_token` to force a fresh login.

## Enable the service

Enable the service in `/etc/rc.conf`:

```sh
sysrc qobuzconnect2mpd_enable=YES
```

The generated rc script uses values equivalent to:

```sh
qobuzconnect2mpd_user="qobuzconnect2mpd"
qobuzconnect2mpd_group="qobuzconnect2mpd"
qobuzconnect2mpd_homedir="/var/db/qobuzconnect2mpd"
qobuzconnect2mpd_config="/usr/local/etc/qobuzconnect2mpd.conf"
qobuzconnect2mpd_flags=""
```

Override them with `sysrc` if needed:

```sh
sysrc qobuzconnect2mpd_config=/path/to/qobuzconnect2mpd.conf
sysrc 'qobuzconnect2mpd_flags=-o /var/tmp/qobuzconnect2mpd.status'
```

To use a different service account or home directory:

```sh
sysrc qobuzconnect2mpd_user=another-account
sysrc qobuzconnect2mpd_group=another-group
sysrc qobuzconnect2mpd_homedir=/var/db/another-account
```

If you run as a non-root user, make sure that user can read the config file and
write any configured status, log, cache, or token paths.

## Start, stop, and inspect

Start the daemon:

```sh
service qobuzconnect2mpd start
```

Check whether it is running:

```sh
service qobuzconnect2mpd status
```

Stop or restart it:

```sh
service qobuzconnect2mpd stop
service qobuzconnect2mpd restart
```

The rc script runs the process under FreeBSD `daemon(8)` in supervised mode
(`-R`), so the daemon is respawned a few seconds after it exits, matching
`Restart=on-failure` in the systemd unit. Tune the delay with
`qobuzconnect2mpd_restart_delay` in `rc.conf` (default `3` seconds).

This is a backstop, not the normal recovery path. The Qobuz cloud closes the
WebSocket periodically (the `qws` JWT is short-lived); the daemon handles that
itself — it mints a fresh JWT from the cached OAuth token and rebuilds the
session, logging `WebSocket connection lost — reconnecting`. The supervisor
only matters for failures it cannot recover from in-process, such as mDNS
being unable to bind, or a crash.

`service qobuzconnect2mpd stop` signals the supervisor, which forwards SIGTERM
to the daemon and exits instead of respawning it. Two pidfiles are written —
the supervisor's, which `rc.subr` tracks, and the daemon's own:

```sh
/var/run/qobuzconnect2mpd/qobuzconnect2mpd.pid        # daemon(8) supervisor
/var/run/qobuzconnect2mpd/qobuzconnect2mpd-child.pid  # qobuzconnect2mpd
```

The supervisor pid is the one `rc.subr` must signal: sending SIGTERM to the
child would only make the supervisor start a fresh one.

The service account's home (`/var/db/qobuzconnect2mpd`, set as
`qconnectstatedir`) holds the OAuth token and device UUID so a stable identity
survives restarts; the pidfiles live separately under `/var/run`. That
directory is owned by the service account but mode `0755`, and the rc script
recreates it on every start (`/var/run` does not survive a reboot). Keeping the
pid outside the `0700` home matters: `rc.subr` reads the pidfile to answer
`service qobuzconnect2mpd onestatus`, so a pid buried in the home would make an
unprivileged status check report a running daemon as stopped — which in turn
misleads anything that polls it, such as the open-media-drc control panel's
renderer toggle.  Override with `qobuzconnect2mpd_rundir` or
`qobuzconnect2mpd_pidfile` in `rc.conf` if you need a different location.

## Logs and troubleshooting

The sample config writes a daemon log to:

```sh
/tmp/qconnect2mpd.log
```

Inspect it with:

```sh
tail -f /tmp/qconnect2mpd.log
```

The service wrapper also sends child stdout and stderr to syslog. This includes
the first-run OAuth URL and startup failures:

```sh
grep qobuzconnect2mpd /var/log/messages
tail -f /var/log/messages
```

Useful checks:

```sh
sockstat -4 -l | grep 9093
sockstat -4 -l | grep 6600
service musicpd status
service qobuzconnect2mpd status
```

If the Qobuz app cannot discover the receiver:

- Confirm the phone or desktop app is on the same LAN as the FreeBSD host.
- Confirm the firewall allows inbound TCP to `qconnectport` (default `9093`).
- Set `qconnectiface` in the config if the host has multiple network
  interfaces and auto-detection picks the wrong one.

If MPD does not play:

- Confirm `mpdhost`, `mpdport`, and `mpdpassword` match your MPD setup.
- Test MPD directly with a client such as `mpc`.
- Check that MPD can play ordinary local or HTTP sources before debugging the
  Qobuz Connect path.
