# Bit-Perfect Parity with the upmpdcli / MPD Reference

**Question.** Does `qobuzconnect2mpd` reproduce audio at exactly the same
quality (bit depth, sample rate, and the actual samples) as the classical
`upmpdcli` + MPD pair? Or does it subtly degrade the stream?

**Answer.** It is bit-perfect — the audio delivered to the DAC is byte-for-byte
identical to what upmpdcli delivers. This document explains *why* by
construction, and records the empirical procedure and result that *prove* it.

---

## Why it is bit-perfect by construction

The playback chain has three stages. Two of them are provably neutral, so the
whole question reduces to one thing: is the source file identical?

### 1. Source file (Qobuz)

Both clients resolve a track the same way — the classic
`track/getFileUrl?track_id=…&format_id=…` endpoint — which returns a direct,
signed CDN URL to a single FLAC file:

```
https://streaming-qobuz-std.akamaized.net/file?...&eid=<id>&fmt=<n>&...
```

The `eid` is Qobuz's **content identifier** for a given (track, format). Two
clients requesting the same track at the same format get the **same `eid`** and
therefore the **same file**; the URLs differ only in the throwaway signing
params (`hmac`, `etsp`, `cid`), which are query string, not file body.

`qobuzconnect2mpd` hands MPD that URL directly. `upmpdcli` serves it through its
`StreamProxy`, which (for a plain GET) `302`-redirects to the very same CDN URL.
Either way MPD fetches the identical bytes. **Neither client transcodes.**

### 2. Transport to MPD

No re-encoding on either path — the original FLAC bytes reach MPD's FLAC
decoder unchanged.

### 3. Decode → DAC (the same MPD)

Both clients drive the **same MPD instance** (`localhost:6600`). Its config
(see `../open-media-drc/mpd/mpd.conf`) alters nothing:

| MPD setting | Effect |
|---|---|
| `mixer_type "disabled"` / output `mixer_type "none"` | volume commands never rescale samples |
| `volume_normalization "no"` | no ReplayGain |
| `OKTO-DAC` = ALSA `hw:0,0`, no forced `format` | no resampling; native rate straight to the DAC |

Because it is literally the same process with the same output config, the PCM
handed to the DAC is identical for both clients given identical input. (Digital
room correction via BruteFIR, if enabled, sits downstream of MPD and applies
equally to both — it is irrelevant to the comparison.)

So bit-perfectness reduces to **stage 1: is the source file identical?** — which
we verify empirically below.

---

## Verification procedure

Both fingerprints are computed because Qobuz **zeroes the FLAC STREAMINFO MD5**
(`metaflac --show-md5sum` returns all zeros), so that field cannot be used:

- **container sha256** — hash of the whole downloaded file (proves byte
  identity).
- **decoded-PCM sha256** — hash of the raw decoded samples (the true audio
  fingerprint; immune to any difference in tags / padding / seektable).

Play the **same track** under each client in turn. While it plays, capture what
MPD is actually streaming and fingerprint it:

```sh
# Grab the URL MPD is currently playing (works for both clients):
URL=$(mpc -h 127.0.0.1 current -f '%file%')

# qobuzconnect2mpd gives a direct CDN URL; upmpdcli gives a proxy URL that
# 302-redirects to the CDN, so follow redirects with -L:
curl -sL -o /tmp/sample.flac "$URL"

# Sanity: same track => same format + same total_samples
metaflac --show-sample-rate --show-bps --show-channels --show-total-samples /tmp/sample.flac

# Container hash (byte identity):
sha256sum /tmp/sample.flac

# Decoded-PCM hash (the verdict — bit-identical audio):
flac -s -d --force-raw-format --endian=little --sign=signed -c /tmp/sample.flac | sha256sum
```

Compare the two clients' hashes. **Equal decoded-PCM sha256 ⇒ bit-identical
audio.** (`total_samples` must match too, otherwise you captured different
tracks/versions.)

---

## Recorded result (2026-06-18)

Track: *"Someone To Believe In"* — Robin Gibb. 16-bit only on Qobuz, so both
clients correctly resolved `fmt=6` (CD quality, 44.1 kHz / 16 bit / stereo).

| | upmpdcli + MPD | qobuzconnect2mpd |
|---|---|---|
| URL `eid` / `fmt` | 47588621 / 6 | 47588621 / 6 |
| sample_rate / bps / ch / samples | 44100 / 16 / 2 / 9286284 | 44100 / 16 / 2 / 9286284 |
| container sha256 | `155fcb0ae40a43abd114fcb336b6aa76f6cd257ce8e3d8985f912a62a1199ebb` | `155fcb0ae40a43abd114fcb336b6aa76f6cd257ce8e3d8985f912a62a1199ebb` |
| decoded-PCM sha256 | `c746d05734c5b9497d8dafd1d119ff488b4649769e5b7b45818a3c2165f157c8` | `c746d05734c5b9497d8dafd1d119ff488b4649769e5b7b45818a3c2165f157c8` |

**Result: byte-for-byte identical** — not merely the same audio, the same file
bytes. Combined with the same-MPD output chain, this is end-to-end proof that
`qobuzconnect2mpd` is bit-perfect and indistinguishable from the upmpdcli/MPD
reference.

---

## Caveats / what to keep an eye on

- **Format selection is the only place the two could ever diverge in quality.**
  `getStreamUrl` requests `qconnectformatid` (default 27 = HiRes) and falls back
  through `{27 → 7 → 6 → 5}`. For a track Qobuz only offers in 16-bit (like the
  one above), `fmt=6` is correct and matches what upmpdcli gets. A genuine
  problem would be qobuzconnect2mpd serving a *lower* format than upmpdcli does
  for the *same* track.
- **Live check:** the status file (`qconnectstatusfile`) shows MPD's real
  decoded format per track (e.g. `24 bit / 192 kHz / stereo`), taken from
  `mpd_status_get_audio_format` — a continuous readout of the quality actually
  playing.
- **Re-running:** capture the *same* track on both clients (verify identical
  `total_samples`); the signed CDN URLs expire after ~10 minutes.
