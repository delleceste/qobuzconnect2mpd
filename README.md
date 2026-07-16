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
4. Playback state (play/pause/seek/track change) is kept in sync between
   the app and MPD in both directions.

HiRes and lossless CMAF/FLAC streams are reconstructed into a shared growing
cache and served to MPD by a lightweight built-in HTTP proxy. Downloads use two
bounded workers; the current and next MusicPD items take priority over queue
prefetch work.

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
meson test -C builddir --print-errorlogs
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
| `qconnecttokenfile` | XDG/HOME data directory | OAuth token cache path |
| `qconnectappid` | value of `qobuzappid` | Qobuz app ID (auto-fetched if empty) |
| `qconnectcfvalue` | value of `qobuzcfvalue` | Qobuz app secret (auto-fetched if empty) |
| `qconnectstatusfile` | `/tmp/qconnect2mpd-status.txt` | Path for the now-playing status file (see `-o` below) |
| `qconnectlogfile` | `/tmp/qconnect2mpd.log` | Path for the log file (errors, retries, now-playing, startup events) |

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
```

Legacy local-file streams may also include the file type and path. Current
segmented streams remain in the private growing cache and do not expose a
persistent path.

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

## Authentication

User authentication is OAuth-only. By default, the resulting token is cached
at `~/.local/share/qconnect2mpd/user_token` with mode `0600`; use
`qconnecttokenfile` to select a service-account path. Subsequent runs reuse it
without re-authenticating. The token directory must be owned by the daemon's
effective user.

If no cached token is available, the daemon prints an OAuth URL at startup:

```
  Not authenticated — open this URL in a browser to log in:

  https://www.qobuz.com/signin/oauth?...

  (after login this device will connect automatically)
```

Open the URL in a browser, log in with your Qobuz account, and the token is
captured automatically via the local redirect handler. Qobuz API requests use
this OAuth token; signed CDN segment requests do not receive it. The `jwt_api`
value delivered by a Connect controller is accepted as protocol metadata but is
not substituted for the verified OAuth `X-User-Auth-Token` flow.

The printed callback path contains a random nonce, accepts only one exchange,
and expires after five minutes. Restart the daemon to generate a new URL if it
expires.

## Queue and seek behavior

The Qobuz queue is authoritative even while only part of it has been resolved
into MusicPD. The selected item is resolved first, followed by MusicPD's next
item; remaining tracks are added incrementally. Remove, insert, reorder,
shuffle, clear, and explicit queue-version updates are acknowledged only after
the corresponding local state has committed.

MusicPD's FLAC decoder needs an exact HTTP length before it can seek. Playback
can begin from the growing cache without that length, but the first seek on an
incomplete segmented track waits for its prioritized reconstruction, reopens
the same queue item with the measured length, and then applies the requested
millisecond position. The renderer reports buffering during this preparation.
Segment proxy URLs use opaque per-process tokens rather than predictable track
IDs because the discovery HTTP listener is reachable on the LAN.

## Bit-perfect audio chain

`qobuzconnect2mpd` is designed to be transparent: the samples your DAC receives
are byte-identical to what Qobuz delivered.  This chapter is an end-to-end
audit of the chain, the places it can silently degrade, and how to verify
bit-perfectness on a running system.

### Pipeline overview

```
Qobuz CDN
    │  encrypted CMAF/FLAC segments (AES-CTR)
    ▼
[ qobuzconnect2mpd ]                       — segstream.cxx
    │  1. AES-CTR decrypt   → byte-identical plaintext
    │  2. Pull FLAC frames out of `mdat`
    │  3. Prepend the STREAMINFO header from the init segment
    ▼
HTTP proxy on 127.0.0.1:9093              — httphandler.cxx
    │  shared growing cache, no transcoding
    │  measured Content-Length and byte ranges after completion
    ▼
MPD (libFLAC decoder)                      — lossless PCM
    ▼
ALSA `hw:N,M` (direct kernel path)
    ▼
DAC
```

The qconnect side is verifiably lossless: AES-CTR is a stream cipher (its
output is deterministic and byte-identical to the plaintext); FLAC frames are
relayed unchanged; the proxy never alters bytes. `file -b` on any segment
materialised during testing reports e.g. `FLAC audio bitstream data, 16 bit,
stereo, 44.1 kHz, 11090856 samples` — i.e. a valid FLAC file with the
expected sample count.

Everything after MPD is **your hardware and MPD config**.  The rest of this
chapter is about getting those right.

### Things that silently break bit-perfectness

| Stage | Risk | How to disable |
|---|---|---|
| MPD volume / replay-gain | rescales samples | `volume_normalization "no"`, `replay_gain_handler "none"` |
| MPD software mixer | scales output | `mixer_type "none"` in audio_output |
| ALSA `plughw:` / `default` | pulls in `dmix` + resampler | use `hw:N,M` directly |
| `auto_resample "yes"` | libasound resamples behind MPD | `auto_resample "no"` |
| `auto_format "yes"` | libasound converts bit-depth | `auto_format "no"` |
| Hardware can't lock source rate | MPD falls back to its internal resampler | use a DAC that natively supports every rate in your library |
| PulseAudio / PipeWire intercept | resampled by the audio server | use `hw:N,M`, not `pulse`/`pipewire` |

### Recommended `mpd.conf`

Global settings (top level):

```
volume_normalization "no"       # no software volume normalisation
replay_gain_handler  "none"     # no replay gain (would alter samples)
samplerate_converter "soxr very high"   # best algorithm for the unavoidable cases
```

`audio_output` block:

```
audio_output {
    type                 "alsa"
    name                 "DAC"
    device               "hw:0,0"   # direct kernel path — no dmix / Pulse / PipeWire
    mixer_type           "none"     # no mixer at all (hardware or software)
    auto_resample        "no"       # do not let libasound resample
    auto_format          "no"       # do not let libasound convert sample formats
    replay_gain_handler  "none"     # redundant but explicit
}
```

Find your card/device numbers with `aplay -l`.  Avoid `default` and
`plughw:` — they route through ALSA's `dmix` which has a fixed sample rate
and a low-quality resampler.

Optional: restrict MPD to formats your DAC natively supports so it can't
silently fall back to something less ideal:

```
allowed_formats "44100:24:2 48000:24:2 88200:24:2 96000:24:2 176400:24:2 192000:24:2"
```

Optional explicit resampler (only used when MPD has to resample):

```
resampler {
    plugin   "soxr"
    quality  "very high"
    thread   "yes"
}
```

### Audit your hardware ceiling

Knowing what rates your DAC can actually lock is essential — anything else
ends up resampled in MPD.

```
cat /proc/asound/card0/codec#0 | grep -E 'rates|bits'
```

A typical built-in Intel HDA codec (laptop) reports something like:

```
rates  [0x560]: 44100 48000 96000 192000
bits   [0xe]:   16 20 24
```

Read that as: **rates supported = the ones listed, nothing else**.  Note in
particular that 88.2 kHz and 176.4 kHz are absent on most built-in codecs;
any Qobuz HiRes track at those rates (frequent in classical reissues from
SACD / DXD masters) will be resampled by MPD before it reaches the DAC.

ALSA's hardware-format probe is also informative:

```
aplay --dump-hw-params -D hw:0,0 /dev/zero
```

Output of interest:

```
RATE: [44100 192000]
Available formats: S16_LE, S32_LE
```

The codec exposes 16-bit and 32-bit containers (Intel HDA carries 24-bit
samples inside an S32_LE container with 8 padding bits — that is still
bit-perfect for 24-bit content; the DAC extracts the 24 valid bits and
ignores the rest).

### Verify in real time

While a track is playing, in another terminal:

```
watch -n 0.5 cat /proc/asound/card0/pcm0p/sub0/hw_params
```

Expected for a 24-bit / 96 kHz Qobuz track:

```
format: S32_LE         ← 24-bit payload, S32 container — bit-perfect
rate: 96000            ← matches source rate
channels: 2
```

If `rate:` doesn't match the source rate (visible on the now-playing line),
MPD resampled.  If `format:` is `S16_LE` for a 24-bit source, MPD truncated.
Either means the chain is not bit-perfect for that track on this hardware.

### When the built-in codec is the bottleneck

For absolute bit-perfectness across every rate Qobuz serves (44.1, 48, 88.2,
96, 176.4, 192 kHz), use a DAC that natively locks all six.  Practically any
modern USB DAC does.  After plugging it in:

```
aplay -l                       # find the new card number
```

then change `device "hw:N,0"` in `mpd.conf` to match.  Nothing else in this
codebase or in MPD's pipeline has to move — the rest of the chain is already
lossless.

### MPD socket layout (independent of bit-perfect)

`bind_to_address` and the music database are completely independent — a single
MPD instance can scan a `music_directory` *and* expose a Unix domain socket
for clients like `qobuzconnect2mpd`:

```
music_directory   "/path/to/music"
db_file           "/var/lib/mpd/database"

bind_to_address   "/run/mpd/socket"   # Unix domain socket
bind_to_address   "127.0.0.1"         # also TCP on localhost (optional)
port              "6600"
```

Multiple `bind_to_address` lines are allowed; each is bound independently. A
value starting with `/` is treated as an absolute path and creates an
`AF_LOCAL` socket. The database, the TCP listener and the Unix socket all
coexist without conflict.

Note: as soon as you set any `bind_to_address`, MPD stops auto-binding
`$XDG_RUNTIME_DIR/mpd/socket` — only what you list is bound.

## systemd

A sample unit file is at `build/qobuzconnect2mpd.service`.  Install it as
`/etc/systemd/system/qobuzconnect2mpd.service` and adjust the `ExecStart`
path and `-c` argument to match your setup.

```sh
systemctl enable --now qobuzconnect2mpd
```

## FreeBSD

Meson can install a FreeBSD `rc.d` service script instead of the systemd unit.
On FreeBSD this is selected automatically; it can also be forced manually:

```sh
meson setup build -Dinit_system=freebsd --prefix=/usr/local
ninja -C build
ninja -C build install
sysrc qobuzconnect2mpd_enable=YES
service qobuzconnect2mpd start
```

See [howto-Freebsd.md](howto-Freebsd.md) for the full FreeBSD installation,
configuration, service management, and troubleshooting guide.

## License

LGPL 2.1 or later.
