pub mod api;

use std::error::Error;

use oauth2::{
    basic::BasicClient, reqwest::http_client, AuthUrl, ClientId, ClientSecret, TokenResponse,
    TokenUrl,
};
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
pub fn get_user_token(
    client_id: i32,
    client_secret: &str,
    scopes: &[api::Scope],
    local_port: i16,
) -> Result<String, Box<dyn Error>> {
    let redirect_url = format!("http://localhost:{}", local_port);
    api::prepare_oauth_request(client_id, client_secret, &redirect_url, scopes)
        .and_then(|state| {
            eprintln!(
                "Open the following URL to get access to osu! API: {}",
                state.auth_url
            );
            let (auth_code, auth_state) = api::listen_for_code(&redirect_url, local_port);
            api::exchange_code(state, &auth_code, &auth_state)
        })
        .map_err(|e| e.into())
}

/// Obtain an OAuth2 client token. It doesn't require user authentication and has guest level access.
pub fn get_client_token(client_id: i32, client_secret: &str) -> Result<String, Box<dyn Error>> {
    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_owned())),
        AuthUrl::new(api::AUTH_URL.to_owned())?,
        Some(TokenUrl::new(api::TOKEN_URL.to_owned())?),
    );

    match client
        .exchange_client_credentials()
        .add_scope(api::Scope::Public.into())
        .request(http_client)
    {
        Ok(resp) => Ok(resp.access_token().secret().to_owned()),
        Err(e) => Err(Box::new(e)),
    }
}
