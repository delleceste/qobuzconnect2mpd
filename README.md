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
| `qconnectstatusfile` | *(disabled)* | Path for the now-playing status file (see `-o` below) |

## Usage

```
qconnect2mpd [-c configfile] [-d] [-o statusfile]

  -c configfile   Path to configuration file (default: /etc/upmpdcli.conf)
  -d              Daemonise (fork to background)
  -o statusfile   Write now-playing status to this file (updated every second);
                  overrides qconnectstatusfile in the config file
```

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
Artist Name - Track Title  [1:23 / 4:56]
FLAC audio bitstream data, 16 bit, stereo, 44.1 kHz
```

The file is updated atomically (temp file + rename) so readers never see a
partial write.  Useful for feeding external displays, OSD scripts, or status
bars.

## Authentication

Qobuz credentials (`qconnectuser` / `qconnectpass`) are used on the first run
to obtain an OAuth token, which is cached at
`~/.local/share/qconnect2mpd/user_token`.  Subsequent runs reuse the cached
token without re-authenticating.

If no credentials are in the config, or if the login endpoint is unavailable,
the daemon prints an OAuth URL at startup:

```
  Not authenticated — open this URL in a browser to log in:

  https://www.qobuz.com/oauth2/...

  (after login this device will connect automatically)
```

Open the URL in a browser, log in with your Qobuz account, and the token is
captured automatically via the local redirect handler.

## systemd

A sample unit file is at `build/qobuzconnect2mpd.service`.  Install it as
`/etc/systemd/system/qobuzconnect2mpd.service` and adjust the `ExecStart`
path and `-c` argument to match your setup.

```sh
systemctl enable --now qobuzconnect2mpd
```

## License

LGPL 2.1 or later.
