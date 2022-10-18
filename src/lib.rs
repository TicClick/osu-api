pub mod api;

use std::error::Error;

use reqwest::{blocking, header};

/// Create an osu! API v2 client with OAuth2 bearer token (may be obtained from [`get_token`]).
pub fn new(raw_token: String) -> blocking::Client {
    let mut headers = header::HeaderMap::new();
    let mut auth = header::HeaderValue::from_str(&format!("Bearer {}", raw_token)).unwrap();
    auth.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, auth);

    blocking::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap()
}

/// Obtain an OAuth2 token using the [authorization code flow](https://www.oauth.com/oauth2-servers/server-side-apps/):
///
/// - Print a URL you need to visit to allow your application (use https://localhost:`{port}` as a redirect URL).
/// - Listen on a local port and wait until you are redirected there by the osu! website.
/// - Extract temporary auth parameters and request the OAuth2 token.
///
/// # Arguments
///
/// * `client_id`, `client_secret`: application data from the osu! website
/// * `scopes`: an array of [API access scopes](https://osu.ppy.sh/docs/index.html#scopes)
/// * `local_port`: any free local port. Must match the one from the application's redirect URL
pub fn get_token(
    client_id: i32,
    client_secret: &str,
    scopes: &[api::Scope],
    local_port: i16,
) -> Result<String, Box<dyn Error>> {
    api::get_token(client_id, client_secret, local_port, scopes)
}
