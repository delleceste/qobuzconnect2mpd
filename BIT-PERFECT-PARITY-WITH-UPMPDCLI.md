# Bit-Perfect Parity with upmpdcli and MusicPD

## Scope

`qobuzconnect2mpd` does not transcode, resample, normalize, or otherwise apply
DSP before handing a FLAC stream to MusicPD. That makes a bit-perfect path
possible, but it is not by itself proof that the samples reaching a DAC are
identical to a reference setup.

There are two separate questions:

1. Does the Qobuz receiver deliver the same decoded PCM for a given track and
   format?
2. Does MusicPD and the configured audio output deliver that PCM without
   mixing, resampling, format conversion, or DSP?

This receiver can be tested for the first property. The second property depends
on the local MusicPD and operating-system audio configuration. Volume behavior
is outside the scope of this document.

## Current Qobuz stream paths

The receiver does not assume that every track is a direct FLAC URL:

1. It establishes a signed stream session with `/session/start`.
2. It prefers `/file/url` for the requested format.
3. When Qobuz returns `url_template`, `key`, and session information, it fetches
   the init fragment and encrypted media fragments, decrypts them with AES-CTR,
   and reconstructs a FLAC stream in a bounded growing cache.
4. The loopback HTTP proxy serves that stream to MusicPD. After reconstruction
   completes, it can report the measured length and satisfy byte ranges.
5. A direct URL returned by `/file/url` is passed through. The classic
   `track/getFileUrl` endpoint is a compatibility fallback.

OAuth is the only user-authentication path. The OAuth token is sent to Qobuz
API requests, not to the signed CDN fragment URLs.

The segmented reconstruction copies FLAC frames without re-encoding, but it
builds a new FLAC container from the init metadata and media fragments.
Consequently, a whole-file hash does not have to match a classic direct FLAC.
The decoded PCM, sample rate, bit depth, channel count, duration, and total
sample count are the meaningful parity checks.

## Verification procedure

Use the same track and effective Qobuz format for both receivers. Signed URLs
expire, so make the two captures close together. First capture the stream
MusicPD is playing through `qobuzconnect2mpd`:

```sh
QCONNECT_URL=$(mpc -h 127.0.0.1 current -f '%file%')
curl -fsSL "$QCONNECT_URL" -o /tmp/qconnect.flac
flac -t /tmp/qconnect.flac
metaflac --show-sample-rate --show-bps --show-channels \
  --show-total-samples /tmp/qconnect.flac
flac -s -d --force-raw-format --endian=little --sign=signed \
  -c /tmp/qconnect.flac | sha256sum
```

The qconnect log identifies the segmented path with a `planned ... segments`
message. Its MusicPD URL contains `/qobuz-segmented/` followed by an opaque,
per-process token. A direct URL instead exercises one of the compatibility
paths and does not validate segmented reconstruction.

Then play the same track and format through the reference upmpdcli setup and
repeat the capture:

```sh
REFERENCE_URL=$(mpc -h 127.0.0.1 current -f '%file%')
curl -fsSL "$REFERENCE_URL" -o /tmp/reference.flac
flac -t /tmp/reference.flac
metaflac --show-sample-rate --show-bps --show-channels \
  --show-total-samples /tmp/reference.flac
flac -s -d --force-raw-format --endian=little --sign=signed \
  -c /tmp/reference.flac | sha256sum
```

Parity requires all of the following:

- both files pass `flac -t`;
- sample rate, bits per sample, channels, and total samples match;
- the decoded-PCM SHA-256 values match.

A matching container SHA-256 is useful on two direct-URL captures, but it is
not required when one side is reconstructed from segmented CMAF.

## What the historical direct-URL test proves

A 2026-06-18 test of the former direct-URL path found identical container and
decoded-PCM hashes for the same 44.1 kHz, 16-bit stereo track through upmpdcli
and `qobuzconnect2mpd`. That result validates the classic direct pass-through
path at that point in time. It does not validate today's segmented
reconstruction path; use the procedure above on a URL confirmed to be
segmented.

## Format and MusicPD checks

The receiver requests `qconnectformatid` and falls back through lower supported
qualities in the order 27, 7, 6, then 5. Compare the effective format, not just
the requested value. The status file reports MusicPD's decoded sample rate,
bit depth, and channel count using `mpd_status_get_audio_format`.

After receiver-level PCM parity is established, verify the MusicPD output
separately. Mixer settings, ReplayGain, DSP filters, resamplers, audio-server
conversion, and hardware format limits can all change the signal downstream of
the receiver. Use the operating system's live audio-device format reporting to
confirm that the output rate and sample format match MusicPD's decoded format.
