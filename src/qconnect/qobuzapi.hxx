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
#include <json/json.h>

namespace QConnect {

// Minimal Qobuz REST API client for qconnect2mpd.
//
// Authentication uses the JWT obtained from the Qobuz app during the
// connect-to-qconnect handshake (ConnectCredentials::api_jwt).  This
// token is already scoped to the current user's session so no separate
// login step is required.
//
// Alternatively, if the JWT is unavailable, falls back to the classic
// user/password token stored in upmpdcli's config (qobuzuser/qobuzpass).

struct TrackStreamInfo {
    std::string stream_url;  // signed HTTPS URL, valid for ~10 min
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

    // Use a JWT obtained from the Qobuz app for authentication.
    // When set, this takes priority over user/password credentials.
    void setJwt(const std::string& jwt) { m_jwt = jwt; }

    // Use classic user+password authentication.
    // Calls /user/login and stores the user_auth_token.
    bool login(const std::string& user, const std::string& pass);

    // OAuth2 flow: exchange the code_autorisation parameter from the Qobuz
    // OAuth redirect URL for a user_auth_token. This is the only login method
    // that works reliably as of April 2026 (Qobuz deprecated /user/login).
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

    // Return the user_auth_token obtained from login() or oauthExchangeCode()
    // (empty if not logged in).
    const std::string& userToken() const { return m_user_token; }

    // Return the app_id (set via constructor or fetched from bundle.js).
    const std::string& appId() const { return m_app_id; }

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
    // and out_jwt, and returns true.  Requires a prior successful login().
    bool fetchQwsToken(std::string& out_endpoint, std::string& out_jwt);

private:
    bool tryGetStreamUrl(uint32_t track_id, int format_id, TrackStreamInfo& out,
                         long* http_code = nullptr);
    // quiet: downgrade non-200 logging to debug (used while probing candidate
    // secrets, where a 400 is expected and not a real error).
    std::string httpGet(const std::string& path,
                         long* http_code_out = nullptr,
                         bool  quiet = false);
    // Sign a request with the classic getFileUrl secret. With secret_override
    // empty, signs with m_app_secret; pass a secret to sign with a different
    // one (e.g. the classic secret for the legacy /track/getFileUrl endpoint).
    std::string buildRequestSignature(const std::string& method_prefix,
                                      const std::map<std::string, std::string>& args,
                                      uint64_t ts,
                                      const std::string& secret_override = "") const;

    std::string m_base_url;
    std::string m_app_id;
    std::string m_app_secret;              // active secret (MD5 suffix for signing)
    std::vector<std::string> m_secret_candidates; // decoded from bundle.js
    // Persistent copy of all bundle.js secrets (m_secret_candidates is cleared
    // once the session secret is confirmed). Used to find the classic secret.
    std::vector<std::string> m_bundle_secrets;
    // Secret that validates the classic API (/track/getFileUrl). Different from
    // m_app_secret, which signs the newer session/file endpoints.
    std::string m_classic_secret;
    std::string m_user_token;              // from /user/login
    std::string m_jwt;                     // from Qobuz app JWT (preferred)
};

} // namespace QConnect
