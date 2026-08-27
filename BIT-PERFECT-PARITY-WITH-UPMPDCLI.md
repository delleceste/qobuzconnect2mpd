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

Which path is used is selected by `qconnectstreammode`.

**`direct` (default).** The classic `track/getFileUrl` endpoint returns a
signed CDN URL for the whole FLAC file. MusicPD's queue does not hold that URL
— those expire after 3600 seconds — but a permanent token
`http://127.0.0.1:<port>/qobuz-direct/<token>`. Each GET resolves the track
afresh and answers `302` with a newly signed URL. MusicPD follows the redirect
(`CURLOPT_FOLLOWLOCATION`) and fetches from the CDN itself.

**No audio passes through this process on the direct path.** The receiver
never sees a sample: it hands MusicPD a URL and MusicPD downloads the same file
the reference setup downloads. Bit-perfection is therefore structural, not
merely empirical — but it is verified below anyway.

**`segmented` / `auto`.** `/session/start` plus `/file/url` return encrypted
CMAF fragments. The receiver measures every fragment's exact reconstructed
length from a short prefix of its box headers, publishes that as a real
`Content-Length`, then fetches, AES-CTR decrypts and reassembles fragments into
a sparse cache which the loopback proxy serves. Fragments may be written out of
order, so a seek fetches only the fragment holding the target offset.

OAuth is the only user-authentication path. The OAuth token is sent to Qobuz
API requests, not to the signed CDN URLs.

The segmented reconstruction copies FLAC frames without re-encoding, but it
builds a new FLAC container from the init metadata and media fragments.
Consequently a whole-file hash need not match a classic direct FLAC on that
path. The decoded PCM, sample rate, bit depth, channel count, duration, and
total sample count are the meaningful parity checks there. On the direct path
the container hash must match as well, and does.

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

Which path a capture exercised is visible in the URL: `/qobuz-direct/`
resolves to a CDN file by redirect, `/qobuz-segmented/` is reconstructed from
CMAF fragments. On the direct path `curl -L` is required, since the first
response is a `302`. The qconnect log marks a segmented track with a
`planned ... segments` message.

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

## Verified results

### 2026-08-27 — direct path with per-request token resolution

Run after the token/`302` indirection was introduced, to confirm that resolving
the URL per GET changes nothing about the bytes. Capture A went through
MusicPD's actual queue URL — token, redirect and all. Capture B resolved the
same track independently with upmpdcli's exact method (`track/getFileUrl`,
signed the way `cdplugins/qobuz/api/raw.py` signs it), bypassing this daemon
entirely.

| | |
|---|---|
| track | Pink Floyd — *Have a Cigar* (Qobuz `eid=355836927`) |
| format | `fmt=7` — 96 kHz / 24-bit stereo |
| size | 115,640,064 bytes, identical on both captures |
| MusicPD decoded | 24 bit / 96 kHz / stereo |

```
container sha256
  bc5b60d94f1c1a33ec05a27385072f4333508d17c7f7848063889be37ef3af4b  A (via token + 302)
  bc5b60d94f1c1a33ec05a27385072f4333508d17c7f7848063889be37ef3af4b  B (upmpdcli method)

decoded-PCM sha256
  12072aab64bb2e785ec8947627a285b1d8ccc3c789c4de1b43559b3bca697665  A
  12072aab64bb2e785ec8947627a285b1d8ccc3c789c4de1b43559b3bca697665  B
```

Identical containers and identical decoded PCM. The indirection is transparent:
a `302` to the CDN delivers exactly what resolving the CDN URL directly
delivers, which is what the reference implementation does.

### 2026-06-18 — direct path, original form

An earlier test of the direct path found identical container and decoded-PCM
hashes for the same 44.1 kHz, 16-bit stereo track through upmpdcli and
`qobuzconnect2mpd`. Superseded by the run above, which covers the same path in
its current form.

### Not yet verified: the segmented path

Neither run exercises CMAF reconstruction. Its exact total length has been
shown to agree with the direct file — for one 176.4 kHz track the measured
fragment lengths summed to 185,884,303 bytes and the 496-byte FLAC header from
the init fragment brings that to 185,884,799, exactly the direct file's
`Content-Length` — but agreeing on length is not agreeing on every sample.
Before relying on `qconnectstreammode = segmented`, run the procedure above
against a `/qobuz-segmented/` URL and compare decoded PCM.

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
