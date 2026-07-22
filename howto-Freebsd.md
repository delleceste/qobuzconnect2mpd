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
username or password belongs in the configuration.

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

A headless service cannot complete a browser login, so it must find a token
that was cached beforehand. Bootstrap it once with `-L`, running as the service
account: `-L` prints a one-time login URL, waits while you open it in any
browser that can reach the daemon host, receives the callback, writes the token
(mode `0600`) into the state directory, and exits. The callback URL is valid for
five minutes and one successful exchange. After it exits, start the service
normally.

Do not use `su - qobuzconnect2mpd`: the account normally has
`/usr/sbin/nologin` as its shell, which produces `This account is currently not
available.` Change the shell temporarily and quote the command passed to `su
-c` so the daemon receives its arguments.

```sh
pw usermod qobuzconnect2mpd -s /bin/sh
su -m qobuzconnect2mpd -c \
  'HOME=/var/db/qobuzconnect2mpd /usr/local/bin/qobuzconnect2mpd \
  -c /usr/local/etc/qobuzconnect2mpd.conf -L'
pw usermod qobuzconnect2mpd -s /usr/sbin/nologin
service qobuzconnect2mpd start
```

If the service ever starts without a cached token it now exits immediately with
an error pointing back at this `-L` bootstrap, rather than running silently
unable to stream.

Alternatively, start the service normally and copy the same first-run URL from
syslog (normally `/var/log/messages`) into your browser. Restart the foreground
process or service to generate a new URL if the callback expires.

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

The rc script runs the process under FreeBSD `daemon(8)` without automatic
restart and stores the child pid in:

```sh
/var/db/qobuzconnect2mpd/qobuzconnect2mpd.pid
```

The service account's home (`/var/db/qobuzconnect2mpd`) doubles as the state
directory: it holds `user_token`, `device.uuid`, and the pidfile. Set
`qconnectstatedir = /var/db/qobuzconnect2mpd` in the config so the token and a
stable device identity survive restarts.

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
