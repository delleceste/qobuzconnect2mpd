/* Copyright (C) 2024 J.F.Dockes
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation; either version 2.1 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program; if not, write to the
 *  Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <map>
#include <mutex>
#include <json/json.h>

namespace QConnect {

class SegmentedTrackRegistry;

// Minimal Qobuz REST API client for qconnect2mpd.
//
// User authentication uses a Qobuz OAuth user token. A QConnect controller may
// also provide a session-scoped API JWT during connect-to-qconnect, but it is
// retained only as protocol metadata and is not used for REST authentication.

// Which Qobuz streaming API to use for playback URLs.
//
// Direct: classic /track/getFileUrl. Returns a signed CDN URL that MPD can
//   fetch itself. The response carries Content-Length and honours byte
//   ranges, which is what libFLAC needs in order to seek.
// Segmented: /session/start + /file/url. Returns encrypted CMAF fragments
//   that must be decrypted and reassembled into FLAC behind the local proxy.
//   The reconstructed stream has no length until it is complete, so MPD
//   cannot seek it.
// Auto: try Direct, fall back to Segmented.
enum class StreamMode { Direct, Auto, Segmented };

// Parse a 'qconnectstreammode' config value. Unknown values yield Direct.
StreamMode streamModeFromString(const std::string& v);
const char* streamModeName(StreamMode m);

struct TrackStreamInfo {
    std::string stream_url;  // signed HTTPS URL, valid for ~10 min
    std::string local_path;  // legacy materialized streams only
    std::string segment_token; // registry key; empty for direct URLs
    std::string mime_type;   // e.g. "audio/flac"
    int         format_id{6};
    uint32_t    duration_ms{0};
    int         sampling_rate{44100}; // Hz (e.g. 44100, 96000, 192000)
    int         bit_depth{-1};       // bits (e.g. 16, 24), -1 when unspecified
    std::string title;
    std::string artist;
};

struct TrackMeta {
    uint32_t    track_id{0};
    std::string title;
    std::string artist;
    std::string album;
    uint32_t    duration_s{0};
};

class QobuzApi {
public:
    // api_base_url: typically "https://www.qobuz.com/api.json/0.2"
    // app_id, app_secret: Qobuz app credentials (from spoofbuz or config)
    QobuzApi(const std::string& api_base_url,
              const std::string& app_id,
              const std::string& app_secret);

    // OAuth2 flow: exchange the code_autorisation parameter from the Qobuz
    // OAuth redirect URL for a user_auth_token. This is the only supported
    // user-authentication method.
    //
    // The OAuth URL that the user should open in a browser is built with
    // buildOAuthUrl(). After login Qobuz redirects to the redirect_url with
    // ?code_autorisation=... appended; pass that code here.
    bool oauthExchangeCode(const std::string& code);

    // Build the Qobuz OAuth browser login URL.
    // redirect_url: the URL Qobuz will redirect to after login, e.g.
    //   "http://192.168.1.5:9093/oauth/callback"
    std::string buildOAuthUrl(const std::string& redirect_url) const;

    // Persist the user_auth_token to a file so it survives restarts.
    bool saveToken(const std::string& path) const;
    // Load a previously saved user_auth_token. Returns true on success.
    bool loadToken(const std::string& path);

    // Return the user_auth_token obtained from oauthExchangeCode().
    // Empty if OAuth has not completed and no cached token was loaded.
    std::string userToken() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_user_token;
    }

    // Return the app_id (set via constructor or fetched from bundle.js).
    std::string appId() const {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        return m_app_id;
    }

    // Fetch app_id and secret candidates dynamically from the Qobuz web player
    // bundle.js.  Called automatically by QcManager when qobuzappid is not
    // configured.  On success sets m_app_id and populates m_secret_candidates;
    // the active secret is selected lazily on the first getStreamUrl() call.
    bool fetchAppCredentials();

    // Get the signed streaming URL for a track.
    // format_id: 5=MP3-320, 6=FLAC, 7=HiRes-96k, 27=HiRes-192k
    bool getStreamUrl(uint32_t track_id, int format_id,
                       TrackStreamInfo& out);

    // Get track metadata (title, artist, album, duration).
    bool getTrackMeta(uint32_t track_id, TrackMeta& out);

    // Fetch a QConnect WebSocket JWT directly from the Qobuz cloud.
    // Calls POST /qws/createToken using the stored user_auth_token.
    // On success populates out_endpoint (e.g. "wss://play.qobuz.com/ws")
    // and out_jwt, and returns true. Requires an OAuth user token.
    bool fetchQwsToken(std::string& out_endpoint, std::string& out_jwt);

    // Configure local HTTP proxy base URL used to serve segmented tracks
    // (e.g. "http://127.0.0.1:9093/qobuz-segmented").
    void setLocalProxyBaseUrl(const std::string& v) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_local_proxy_base_url = v;
    }

    // Registry used by planSegmentedTrack to publish track plans for the
    // HTTP proxy to stream from.  Must be set before calling getStreamUrl().
    void setSegmentedRegistry(SegmentedTrackRegistry* r) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_seg_registry = r;
    }

    // Selects which streaming API getStreamUrl() uses. Defaults to Direct
    // because only direct CDN URLs are seekable; see StreamMode.
    void setStreamMode(StreamMode m) {
        std::lock_guard<std::recursive_mutex> lock(m_mutex);
        m_stream_mode = m;
    }

private:
    bool ensureStreamSession();
    bool startStreamSession();
    bool tryFileUrl(uint32_t track_id, int format_id, TrackStreamInfo& out,
                    long* http_code = nullptr);
    bool tryGetStreamUrl(uint32_t track_id, int format_id, TrackStreamInfo& out,
                         long* http_code = nullptr);
    // Build a SegmentedTrackPlan, register it, and populate `out` with the
    // proxy URL that MPD will request to stream the track on demand.
    bool planSegmentedTrack(const Json::Value& root, uint32_t track_id,
                             int format_id, TrackStreamInfo& out);
    std::string httpGet(const std::string& path,
                         long* http_code_out = nullptr,
                         bool quiet = false);
    std::string httpPostForm(const std::string& path,
                             const std::map<std::string, std::string>& form,
                             long* http_code_out = nullptr);
    std::string buildRequestSignature(const std::string& method_prefix,
                                      const std::map<std::string, std::string>& args,
                                      uint64_t ts,
                                      const std::string& secret) const;

    mutable std::recursive_mutex m_mutex;
    std::string m_base_url;
    std::string m_app_id;
    std::string m_app_secret;              // active secret (MD5 suffix for signing)
    std::vector<std::string> m_secret_candidates; // decoded from bundle.js
    // Session selection consumes m_secret_candidates, but the classic
    // /track/getFileUrl endpoint may require a different bundle secret.
    std::vector<std::string> m_bundle_secrets;
    std::string m_classic_secret;          // cached classic API secret
    std::string m_user_token;              // from OAuth exchange/cache
    std::string m_stream_session_id;       // from /session/start
    uint64_t    m_stream_session_expires_at{0}; // unix seconds
    std::string m_stream_session_infos;    // from /session/start
    std::string m_local_proxy_base_url;
    SegmentedTrackRegistry* m_seg_registry{nullptr}; // not owned
    StreamMode  m_stream_mode{StreamMode::Direct};
};

} // namespace QConnect
