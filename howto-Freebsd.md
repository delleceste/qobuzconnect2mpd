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
```

`-Dinit_system=freebsd` forces FreeBSD `rc.d` support.  On a native FreeBSD
host, `-Dinit_system=auto` also selects it automatically:

```sh
meson setup build --prefix=/usr/local
```

Use `-Dinit_system=none` if you want only the binary and configuration file.

## Install

Install as root:

```sh
ninja -C build install
```

This installs:

| File | Purpose |
|------|---------|
| `/usr/local/bin/qobuzconnect2mpd` | daemon executable |
| `/usr/local/etc/qobuzconnect2mpd/qobuzconnect2mpd.conf` | sample configuration |
| `/usr/local/etc/rc.d/qobuzconnect2mpd` | FreeBSD service script |

If you use a different `--prefix`, the paths follow that prefix.

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

Edit the installed configuration:

```sh
ee /usr/local/etc/qobuzconnect2mpd/qobuzconnect2mpd.conf
```

At minimum, check:

```conf
qconnectfriendlyname = FreeBSD MPD
mpdhost = localhost
mpdport = 6600
qconnectformatid = 27
```

Authentication is OAuth-only. Set a persistent token-cache path:

```conf
qconnecttokenfile = /var/db/qobuzconnect2mpd/user_token
```

On first start, the daemon prints an OAuth URL in the service log. Open that URL
in a browser on the same LAN and complete the login flow. The cached token is
created with mode `0600`. The callback URL is valid for five minutes and one
successful exchange; restart the service to generate another URL if needed.

## Enable the service

Enable the service in `/etc/rc.conf`:

```sh
sysrc qobuzconnect2mpd_enable=YES
```

The default rc script uses:

```sh
qobuzconnect2mpd_config="/usr/local/etc/qobuzconnect2mpd/qobuzconnect2mpd.conf"
qobuzconnect2mpd_flags="-c ${qobuzconnect2mpd_config}"
```

Override them with `sysrc` if needed:

```sh
sysrc qobuzconnect2mpd_config=/path/to/qobuzconnect2mpd.conf
sysrc 'qobuzconnect2mpd_flags=-c /path/to/qobuzconnect2mpd.conf -o /var/tmp/qobuzconnect2mpd.status'
```

To run the daemon as a dedicated user, create a writable state directory and
set the service account:

```sh
pw useradd qobuzconnect2mpd -d /nonexistent -s /usr/sbin/nologin
install -d -o qobuzconnect2mpd -g qobuzconnect2mpd -m 700 /var/db/qobuzconnect2mpd
sysrc qobuzconnect2mpd_runas=qobuzconnect2mpd
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

The rc script runs the daemon under FreeBSD `daemon(8)` and stores the pid in:

```sh
/var/run/qobuzconnect2mpd.pid
```

## Logs and troubleshooting

The sample config writes a daemon log to:

```sh
/tmp/qconnect2mpd.log
```

Inspect it with:

```sh
tail -f /tmp/qconnect2mpd.log
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
