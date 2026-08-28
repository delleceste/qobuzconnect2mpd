# Streaming transport audit and future work

Audit date: 2026-08-28

Scope: direct-URL and CMAF streaming, queue-to-playback handover, segmented
seeking, and the uncommitted changes on top of `71db2d6`. The comparison
baseline is `../qbz` at `c4cc755fd` (QBZ 2.0.2-era). Existing local changes
were reviewed in place and were not modified by this audit.

## Executive summary

Direct URL mode should remain the default. It is fast and reliable because it
gives MPD/libFLAC the original CDN-hosted FLAC object with a known
`Content-Length` and normal HTTP byte-range semantics. The signed URL is
resolved lazily for each local HTTP request, so it is fresh when MPD needs it.
MPD can stream, probe, reconnect, and seek using the mature CDN path without
this process downloading, decrypting, ordering, and re-serving every CMAF
fragment.

CMAF mode is a compatibility path, not an equivalent transport. It first
fetches and parses an init fragment, derives and unwraps keys, downloads many
encrypted media fragments, decrypts and reconstructs a FLAC byte stream, and
serves the growing result to MPD through the local HTTP server. A seek also has
to translate time to a reconstructed byte offset and prioritize fragments that
may not exist locally yet. That creates request amplification, CDN-rate-limit
exposure, signed-URL expiry, more concurrency state, head-of-line waits, and a
larger timeout surface.

```text
direct: MPD/libFLAC -> local resolver -> one native CDN FLAC (Range)

CMAF:   MPD/libFLAC -> local growing stream -> scheduler -> N CDN fragments
                                             -> decrypt -> reconstruct FLAC
```

The latest CMAF work substantially improves exact stream geometry, sparse
segment caching, and target-directed fetching. However, the current uncommitted
implementation has two memory/concurrency hazards and one seek ordering bug
that should be fixed before it is merged.

## Comparison with QBZ

The repositories serve different players, so code cannot be copied wholesale,
but these QBZ behaviors are directly relevant:

| Concern | This implementation | `../qbz` reference | Conclusion |
| --- | --- | --- | --- |
| Direct playback | Lazy per-GET signed URL, handed to MPD | Resolves the native stream for its player | Keep as default; it avoids CMAF reconstruction. |
| Segment count | Init-table count normally; JSON fallback subtracts one | `n_segments` is the audio-fragment count and QBZ fetches `1..=n_segments` | The fallback is likely off by one. |
| Init table | Retains byte length; discards sample count | `crates/qbz-cmaf/src/parser.rs` retains `{byte_len, sample_count}` | Keep sample counts for exact time-to-segment seeks. |
| Parallel fetch | Six 1 MiB ranges inside one fragment | `crates/qbz-qobuz/src/cmaf.rs` uses three fragment fetches and a 500 ms per-slot cooldown | Six connections need measurement and rate awareness. |
| Retries | Retries every error with fixed waits | `crates/qbz-qobuz/src/retry.rs` retries transport, 5xx, and 429; other 4xx are terminal | Add typed classification, jitter, and `Retry-After`. |
| Repeated 403 | No shared protection | `forbidden_breaker.rs` opens after three 403s and increases cooldown | Add a shared breaker to avoid a WAF/IP block. |
| Queue identity | Recent changes detect/log mismatches | `qconnect-app/src/queue_resolution.rs` resolves queue-item ID first, then guarded track/next identity | Logging is not recovery. |
| Parser hardening | Bounds-checks raw init data; hex decoding is permissive | QBZ rejects malformed lengths and invalid seed hex | Make hex parsing strict as defense in depth. |

The targeted QBZ/QConnect protocol work from the previous comparison is already
present: WebSocket liveness, callbacks outside the receive loop, queue
mutation/version handling, autoplay state, playback-error handling, and
disconnect recovery. QBZ changes after that point are mostly unrelated UI/app
work. The useful remaining differences are the transport protections and queue
resolution above.

## Findings

### P0 — fix before merging the current changes

- [ ] **Remove the MPD seek timeout use-after-free.**
  `src/qconnect/mpdctl.cxx`, in `MpdCtl::applyPlayback`, constructs
  `TimeoutRestore` with the current `m_conn`. A failed seek frees that
  connection and reconnects, but the scope destructor later calls
  `mpd_connection_set_timeout` on the freed original pointer. Restore the
  timeout before freeing and apply/restore it to each current connection; never
  let a raw connection pointer span reconnect logic. Test failed-first-seek
  recovery under ASan.

- [ ] **Eliminate overlapping writes in parallel range fallback.**
  `fetchSegmentBytes` lets workers copy non-overlapping ranges into `raw`.
  If a server ignores `Range`, one worker copies the complete object while
  other workers may still copy partial ranges. The flag is set after the copy
  and does not synchronize the overlapping writes: this is a C++ data
  race/undefined behavior. Keep results private and assemble after joining, or
  synchronize whole-object publication without concurrent writes. Test a
  range-ignoring server under TSan.

- [ ] **Apply a CMAF seek hint only after no-op seek suppression.**
  `QcManager::applyState` redirects `wanted_segment` and `read_segment`
  before deciding that a position update is already within 1500 ms and
  suppressing the seek. A routine state echo can pull the downloader away from
  the decoder even though MPD never seeks. Move the hint below the final
  `has_position` decision and add a regression test.

### P1 — reliability and correctness

- [ ] **Preserve seek targets before download state exists.**
  `hintSegmentedTrackTarget` returns when `m_download_state` has not been
  created, so queue-load hints are timing-dependent. Store a pending target on
  the plan and consume it atomically when state is created.

- [ ] **Fix and verify the JSON `n_segments` fallback.**
  `buildSegmentedTrackPlan` allocates `json_n_segments_fallback - 1`
  entries. QBZ's tested meaning is an audio-fragment count numbered
  `1..=n_segments`; subtraction recreates its former “missing final ~9
  seconds” bug. Verify a captured response, remove the subtraction, and test a
  final-fragment sentinel.

- [ ] **Retain `sample_count` and seek by samples, not byte ratio.**
  The parser discards this init-table field. Mapping
  `duration_fraction * audio_bytes` is inaccurate for variable-bitrate FLAC.
  Store cumulative samples, select the owning fragment, and use its start byte.
  Validate totals against FLAC metadata and duration.

- [ ] **Replace blanket retries with a typed policy.**
  Return `CURLcode` and HTTP status. Retry connection failures, timeouts,
  5xx, and 429 with bounded exponential backoff and jitter; honor
  `Retry-After`; stop for terminal 4xx. Retry an individual failed chunk
  without discarding all successful chunks.

- [ ] **Add a shared 403 circuit breaker.**
  Three consecutive authenticated 403s should open a no-network cooldown,
  allow one probe after expiry, and increase cooldown after a failed probe. A
  success closes it. A 403 should abort quality fallback because it is not
  evidence that only one quality is unavailable.

- [ ] **Re-evaluate six parallel range connections.**
  QBZ uses three concurrent fragment requests and a 500 ms per-slot cooldown
  after observing Akamai throttling above roughly five requests per IP. Measure
  startup and sustained formats 6/7/27 with playback plus prefetch. Begin with
  a conservative global cap, adapt down on 429/503, and split ranges only when
  measured benefit justifies it.

- [ ] **Bound all untrusted transfer sizes.**
  `fetchSegmentBytes` converts a server-provided `Content-Range` total to
  `size_t` and allocates it without a practical maximum; ordinary response
  buffering is also unbounded. Add checked conversions and limits for init
  fragments, media fragments, reconstructed tracks, table counts, and bodies.
  Reject contradictory range/content lengths.

- [ ] **Make deadlines and cancellation end-to-end consistent.**
  Segment fetches have connect and low-speed limits but no absolute deadline.
  The segmented reader may wait 120 seconds, libmicrohttpd uses 30 seconds, and
  MPD seek handling uses another value. Define one seek budget, propagate
  cancellation through curl, and test a fragment that stalls while remaining
  above the low-speed threshold.

- [ ] **Refresh stale CMAF plans at playback time.**
  Segmented signed templates are resolved while loading the queue, so later
  tracks can begin after expiry. Resolve lazily or refresh on expiry/403/410
  with single-flight replacement, safely retiring the stale plan.

- [ ] **Make `auto` mode truly direct-first.**
  `QobuzApi::getStreamUrl` establishes a CMAF stream session before trying
  direct whenever fallback is enabled. Delay that work until direct resolution
  fails, so the success path pays no unrelated API latency.

- [ ] **Reconcile queue identity instead of only logging mismatch.**
  Resolve by `queue_item_id` first and validate its track; use a unique
  `track_id` plus next/order context only as a guarded fallback. Request
  authoritative state if ambiguous or stale. Cover duplicates, shuffle,
  concurrent mutation, and stale snapshots.

- [ ] **Fail closed when local token generation fails.**
  `SegmentedTrackRegistry::tokenForTrack` falls back to predictable
  `track_id_format.flac` when random/digest setup fails, contradicting its
  LAN opacity. Propagate secure-random/HMAC failure and do not manufacture weak
  entropy from PID and a clock.

- [ ] **Prune direct-token state.**
  `QcManager::m_direct_tokens` grows for process lifetime. Remove tokens on
  queue replacement/deactivation and retain only active or pinned requests.

### P2 — maintainability, diagnostics, and validation

- [ ] Add fault-injection HTTP tests for ignored/short/malformed ranges,
  inconsistent totals, 403/404/429/5xx, delayed bodies, cancellation, URL
  refresh, and one failed chunk among successful chunks.
- [ ] Add scheduler tests for hint-before-state, concurrent readers,
  current/next competition, reversed seeks, retirement, and shutdown during
  curl work.
- [ ] Run new concurrency tests under ASan and TSan in CI. Existing tests use
  synthetic/growing plans but do not execute the new parallel range branch.
- [ ] Validate init-table count against `/file/url n_segments`; define which
  source is authoritative on mismatch.
- [ ] Reject every invalid hex nibble instead of relying on permissive
  `sscanf` conversion.
- [ ] Add counters for mode selection, resolution latency, HTTP status, retry,
  breaker state, throughput, buffer lead, selected target, and first-audio
  latency. Never log signed URLs, auth headers, keys, or local tokens.
- [ ] Update stale comments/configuration text claiming CMAF always has unknown
  length or cannot seek. Exact geometry exists when the init table is valid,
  while direct remains the lower-risk default.
- [ ] Extend `tools/watch-qbz.sh` review coverage to `qbz-cmaf`, Qobuz
  retry/breaker code, and `qconnect-app` queue resolution.
- [ ] Live-test formats 6/7/27: compare reconstructed CMAF with direct FLAC
  after decode, including first/last samples, cold start, long pause,
  reconnect, next/previous, repeated seeks, shuffle, and queue mutation.

## Delivery plan

1. **Safety patch:** fix the stale MPD pointer, range-write race, and hint
   ordering; add focused regression tests and run ASan/TSan.
2. **Correct seek model:** retain sample counts, fix fallback count, persist
   pending targets, and align timeout/cancellation.
3. **Network resilience:** add typed failures, chunk retry, backoff/jitter,
   `Retry-After`, the 403 breaker, transfer limits, and URL refresh.
4. **Protocol correctness:** implement queue identity reconciliation with
   duplicate/shuffle/mutation coverage.
5. **Tune with evidence:** benchmark conservative/adaptive concurrency across
   qualities and networks; decide from first-audio, underrun, and error data.
6. **Harden and document:** secure tokens, prune registries, add observability,
   update mode documentation, and complete live parity tests.

## Acceptance gates

- Direct stays the default and makes no CMAF-session call on a successful path,
  including `auto`.
- No sanitizer findings in seek retry, range fallback, cancellation, or
  shutdown tests.
- CMAF includes the final fragment and decodes to the same PCM as direct FLAC
  for representative lossless and hi-res tracks.
- A state echo does not change scheduler priority; a real seek selects the
  sample-correct fragment before MPD asks for it.
- 403/404 do not create retry/quality storms; 429/5xx/transport errors recover
  within bounded request and time budgets.
- Malformed, slow, range-ignoring, and expired-URL servers cannot cause
  unbounded allocation, indefinite transfer, or overlapping writes.
- Queue commands select the correct duplicate occurrence through shuffle and
  concurrent mutation.
