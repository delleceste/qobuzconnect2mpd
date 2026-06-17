# qobuzconnect2mpd

A Qobuz Connect receiver daemon that bridges the Qobuz mobile / desktop app to
[MPD](https://www.musicpd.org/) (Music Player Daemon).  Works similarly to
Spotify Connect: the Qobuz app discovers the device on the local network (via
mDNS), you cast a track or queue to it, and the audio plays through MPD.

## How it works

1. The daemon advertises itself on the LAN using mDNS (Bonjour/Avahi-style).
2. The Qobuz app discovers it and opens a WebSocket session to the Qobuz
   Connect cloud relay.
3. When the user presses Play, the daemon resolves stream URLs from the Qobuz
   API and loads them into MPD's queue.
4. Playback state (play/pause/seek/volume/track change) is kept in sync between
   the app and MPD in both directions.

HiRes and lossless CMAF/FLAC streams are downloaded, assembled locally, and
served to MPD via a lightweight built-in HTTP proxy.

## Dependencies

| Library | Package (Debian/Ubuntu) |
|---------|------------------------|
| libcurl | `libcurl4-openssl-dev` |
| libmicrohttpd | `libmicrohttpd-dev` |
| jsoncpp | `libjsoncpp-dev` |
| libmpdclient | `libmpdclient-dev` |
| openssl | `libssl-dev` |

Build tool: [Meson](https://mesonbuild.com/) + Ninja.

## Building

```sh
meson setup builddir
ninja -C builddir
```

The binary is `builddir/qobuzconnect2mpd`.

## Configuration

The daemon reads its configuration from `/etc/upmpdcli.conf` (same file as
upmpdcli) unless overridden with `-c`.  A standalone example config is
provided at `conf/qobuzconnect2mpd.conf`.

### Relevant config keys

| Key | Default | Description |
|-----|---------|-------------|
| `qconnectfriendlyname` | value of `friendlyname` | Device name shown in the Qobuz app |
| `qconnectport` | `9093` | HTTP port for device endpoints |
| `qconnectformatid` | value of `qobuzformatid` or `27` | Stream quality: 5=MP3, 6=FLAC, 7=HiRes-96k, 27=HiRes-192k |
| `qconnectiface` | *(auto)* | Network interface for mDNS |
| `qconnectsockpath` | *(disabled)* | Unix socket for IPC with upmpdcli |
| `mpdhost` | `localhost` | MPD hostname |
| `mpdport` | `6600` | MPD port |
| `mpdpassword` | *(none)* | MPD password |
| `qconnectuser` | value of `qobuzuser` | Qobuz account e-mail |
| `qconnectpass` | value of `qobuzpass` | Qobuz account password |
| `qconnectappid` | value of `qobuzappid` | Qobuz app ID (auto-fetched if empty) |
| `qconnectcfvalue` | value of `qobuzcfvalue` | Qobuz app secret (auto-fetched if empty) |
| `qconnectstatusfile` | `/tmp/qconnect2mpd-status.txt` | Path for the now-playing status file (see `-o` below) |
| `qconnectlogfile` | `/tmp/qconnect2mpd.log` | Path for the log file (errors, retries, now-playing, startup events) |

## Usage

```
qconnect2mpd [-c configfile] [-d] [-L] [-o statusfile]

  -c configfile   Path to configuration file (default: /etc/upmpdcli.conf)
  -d              Daemonise (fork to background)
  -L, --login     Interactive OAuth login: print the Qobuz login URL, wait for
                  the browser redirect, cache a token, then exit
  -o statusfile   Write now-playing status to this file (updated every second);
                  overrides qconnectstatusfile in the config file
```

## Authentication

Qobuz `user`/`password` no longer authenticate third-party clients (their
`/user/login` endpoint was closed during the cloud migration). The only way in
is **OAuth**, which yields a token that is cached and reused on every restart.

Bootstrap it once, interactively:

```sh
qobuzconnect2mpd -c <configfile> -L
```

This prints a Qobuz login URL; open it in a browser, log in, and the daemon
catches the redirect and caches the token (under
`~/.local/share/qconnect2mpd/`). After that the service starts normally.

In service mode the daemon **refuses to start** (exits non-zero) when there is
no cached OAuth token — run `-L` first.

### Startup log

On start the daemon prints:

```
qconnect2mpd: config: /etc/upmpdcli.conf
qconnect2mpd: MPD localhost:6600
qconnect2mpd: MPD connected OK (localhost:6600)
```

### Now-playing console output

When a track starts playing the daemon prints to stdout:

```
▶  Artist Name - Track Title
   FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz
   /tmp/qconnect2mpd-segmented/12345_27_1234567890.flac
```

### Status file (`-o`)

When `-o statusfile` is given the daemon writes (and rewrites every second):

```
[playing] Artist Name - Track Title  [1:23 / 4:56]
FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz
```

Line 1 is prefixed with the current playback state: `[playing]`, `[paused]`,
or `[stopped]`.  The file is updated atomically (temp file + rename) so readers
never see a partial write.  When the daemon stops it removes the status file.
Useful for feeding external displays, OSD scripts, or status bars.

### Log file (`qconnectlogfile`)

When `qconnectlogfile` is set, timestamped entries are appended for:

- Startup events (config path, MPD connection result)
- Now-playing track changes
- Segment fetch errors and retries (with error reason and segment N/total)
- Qobuz API / WebSocket connection events

```
2026-05-15 14:32:01 [OUT] qconnect2mpd: MPD connected OK (localhost:6600)
2026-05-15 14:32:15 [INF] ▶  Aphex Twin - Xtal
2026-05-15 14:35:02 [ERR] QobuzApi: segment 18/72 fetch failed (HTTP 503) for ... — retrying
2026-05-15 14:35:07 [ERR] QobuzApi: segment 18/72 fetch failed (HTTP 503) for ... — giving up
```

Log levels: `[OUT]` normal output, `[INF]` informational, `[ERR]` errors.
The file is truncated (not appended) on each daemon restart, so the log always
reflects the current session only.

## systemd

A sample unit file is at `build/qobuzconnect2mpd.service`.  Install it as
`/etc/systemd/system/qobuzconnect2mpd.service` and adjust the `ExecStart`
path and `-c` argument to match your setup.

```sh
systemctl enable --now qobuzconnect2mpd
```

## License

LGPL 2.1 or later.
