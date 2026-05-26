# FreeBSD how-to

This guide installs `qobuzconnect2mpd` as a FreeBSD `rc.d` service.

## Install dependencies

Install the build tools, libraries, and MPD:

```sh
pkg install meson ninja pkgconf curl libmicrohttpd jsoncpp libmpdclient openssl mpd
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
sysrc mpd_enable=YES
service mpd start
```

Make sure MPD listens where `qobuzconnect2mpd` will connect.  The default
`qobuzconnect2mpd` settings expect TCP on localhost port 6600:

```conf
bind_to_address "127.0.0.1"
port "6600"
```

Restart MPD after changing its configuration:

```sh
service mpd restart
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

Add Qobuz credentials if you want password login at startup:

```conf
qconnectuser = your-account@example.com
qconnectpass = your-password
```

If credentials are omitted, the daemon prints an OAuth URL in the service log
when it starts.  Open that URL in a browser on the same LAN and complete the
login flow.

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

To run the daemon as a dedicated user, create the user and set:

```sh
pw useradd qobuzconnect2mpd -d /nonexistent -s /usr/sbin/nologin
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
service mpd status
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
