# qobuzconnect2mpd

A Qobuz Connect receiver daemon that bridges the Qobuz mobile / desktop app to
[MPD](https://www.musicpd.org/) (Music Player Daemon).  Works similarly to
Spotify Connect: the Qobuz app discovers the device on the local network (via
mDNS), you cast a track or queue to it, and the audio plays through MPD.

## How it works

1. The daemon advertises itself on the LAN using mDNS (Bonjour/Avahi-style).
2. The Qobuz app discovers it and opens a WebSocket session to the Qobuz
   Connect cloud relay.
3. When the user presses Play, the daemon resolves the track through Qobuz's
   authenticated `/file/url` API and loads a playable URL into MPD's queue.
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

The daemon reads its configuration from `/etc/upmpdcli.conf` (the same file as
upmpdcli) unless overridden with `-c`. The tracked standalone template is
`conf/qobuzconnect2mpd.conf.example`. For a checkout-local configuration:

```sh
cp conf/qobuzconnect2mpd.conf.example conf/qobuzconnect2mpd.conf
```

Edit the copied file and start the daemon with
`-c conf/qobuzconnect2mpd.conf`. The live `.conf` file is ignored by Git. Meson
installs the executable and the selected service definition, but does not
install or overwrite the live configuration.

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
| `qconnectstatusfile` | *(none)* | Path for the now-playing status file; the sample uses `/tmp/qconnect2mpd-status.txt` |
| `qconnectlogfile` | *(none)* | Path for the log file; the sample uses `/tmp/qconnect2mpd.log` |
| `qconnectloglevel` | `error` | QConnect log verbosity: `error`, `info`, or `debug` |

## Usage

```
qobuzconnect2mpd [-c configfile] [-d] [-o statusfile] [-v|--debug]

  -c configfile   Path to configuration file (default: /etc/upmpdcli.conf)
  -d              Daemonise (fork to background)
  -o statusfile   Write now-playing status to this file (updated every second);
                  overrides qconnectstatusfile in the config file
  -v, --debug     Enable debug logging for this run
```

Debug traces are written to `qconnectlogfile`, not stdout.

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
   track /tmp/qobuzconnect2mpd-1001/cache/track_415828162_27_1234_1.flac [44100,16,2] playing...
```

Segmented streams use a visible `0600` growing cache file while retained. The
numeric component in `/tmp/qobuzconnect2mpd-<uid>/cache` is the daemon's
effective user ID. The daemon removes the file on cache eviction or shutdown
and clears files left by a previous crashed process on startup. The HTTP proxy
reads the already-open descriptor for MusicPD, so removing the pathname cannot
truncate active playback.

### Status file (`-o`)

When `-o statusfile` is given the daemon writes (and rewrites every second):

```
[playing] Artist Name - Track Title  [1:23 / 4:56]
16 bit / 44.1 kHz / stereo
```

Line 1 is prefixed with the current playback state: `[playing]`, `[paused]`,
or `[stopped]`.  The file is updated atomically (temp file + rename) so readers
never see a partial write.  When the daemon stops it removes the status file.
Useful for feeding external displays, OSD scripts, or status bars.

### Log file (`qconnectlogfile`)

When `qconnectlogfile` is set, timestamped entries are written for:

- Startup events (config path, MPD connection result)
- Now-playing track changes
- Segmented FLAC reconstruction start and completion
- Segment fetch errors and retries (with error reason and segment N/total)
- Qobuz API / WebSocket connection events

```
2026-05-15 14:32:01 [OUT] qconnect2mpd: MPD connected OK (localhost:6600)
2026-05-15 14:32:14 [INF] QobuzApi: track /tmp/qobuzconnect2mpd-1001/cache/track_415828162_27_1234_1.flac [44100,16,2] reconstructing 31 encrypted Qobuz audio segments (initialization segment 0 already parsed)
2026-05-15 14:32:15 [INF] track /tmp/qobuzconnect2mpd-1001/cache/track_415828162_27_1234_1.flac [44100,16,2] playing: Aphex Twin - Xtal
2026-05-15 14:32:17 [INF] QobuzApi: track /tmp/qobuzconnect2mpd-1001/cache/track_415828162_27_1234_1.flac [44100,16,2] complete: 31/31 segments, 116118901 bytes
2026-05-15 14:35:02 [ERR] QobuzApi: segment 18/72 fetch failed (HTTP 503) for ... — retrying
2026-05-15 14:35:07 [ERR] QobuzApi: segment 18/72 fetch failed (HTTP 503) for ... — giving up
```

At debug level, every reconstructed audio segment also produces a line such as
`[segment 2/31] in progress (6%)`. This percentage counts completed media
segments; it is not a byte percentage because Qobuz's segment byte table is
only an estimate. Segment 0 is the initialization segment used to derive the
FLAC header and is fetched before the 31 audio segments shown here.
The compact audio triplet is `sample-rate,bits-per-sample,channels`, read from
FLAC STREAMINFO during reconstruction and from MusicPD when playback begins.

Log levels: `[OUT]` normal output, `[INF]` informational, `[DEB]` debug, and
`[ERR]` errors.
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

For playback, the daemon prefers the current `/session/start` plus `/file/url`
flow. A segmented response is decrypted and reconstructed into FLAC behind the
loopback HTTP proxy. A direct URL returned by that API can be passed through,
and the classic `track/getFileUrl` API remains a compatibility fallback. No
username/password login path is used.

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

`qobuzconnect2mpd` does not transcode or apply DSP. The preferred segmented
path decrypts Qobuz's CMAF fragments and reconstructs a FLAC stream for MPD;
the direct-URL compatibility path passes the original stream to MPD. Actual
DAC output still depends on the selected MusicPD output, mixer, resampler, and
hardware. See [BIT-PERFECT-PARITY-WITH-UPMPDCLI.md](BIT-PERFECT-PARITY-WITH-UPMPDCLI.md)
for the current verification scope and a decoded-PCM comparison procedure.

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

The qconnect data path is intended to be lossless: AES-CTR decryption recovers
the fragment plaintext, FLAC frames are copied without re-encoding, and the
proxy does not perform audio conversion. The reconstructed FLAC container is
not necessarily byte-identical to a classic direct-download FLAC, so decoded
PCM hashes, format fields, duration, and total sample count are the relevant
parity checks.

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

### Example Linux/ALSA `mpd.conf`

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

On Linux, find your card/device numbers with `aplay -l`. Avoid `default` and
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

then change `device "hw:N,0"` in `mpd.conf` to match. Re-run the decoded-PCM
and hardware-format checks after changing the output path.

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

Meson generates a user unit as `builddir/qobuzconnect2mpd.service` and installs
it under the configured systemd user-unit directory. Ensure its `%E` config
path exists before starting it.

```sh
systemctl --user enable --now qobuzconnect2mpd
```

## FreeBSD

Meson can install a FreeBSD `rc.d` service script instead of the systemd unit.
On FreeBSD this is selected automatically; it can also be forced manually:

```sh
meson setup build -Dinit_system=freebsd --prefix=/usr/local
ninja -C build
ninja -C build install
cp conf/qobuzconnect2mpd.conf.example conf/qobuzconnect2mpd.conf
# Edit conf/qobuzconnect2mpd.conf before starting the service.
sysrc qobuzconnect2mpd_enable=YES
service qobuzconnect2mpd start
```

The generated `rc.d` script points to the live, ignored configuration in the
source checkout. Meson does not install that file. Keep the checkout at its
configured path, or override `qobuzconnect2mpd_config` in `rc.conf`.

See [howto-Freebsd.md](howto-Freebsd.md) for the full FreeBSD installation,
configuration, service management, and troubleshooting guide.

## License

LGPL 2.1 or later.
