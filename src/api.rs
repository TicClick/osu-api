use std::error::Error;
use std::fmt;

use std::{
    io::{prelude::*, BufReader},
    net::TcpListener,
};

use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::url::ParseError;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    TokenResponse, TokenUrl,
};
use reqwest::Url;

pub const AUTH_URL: &str = "https://osu.ppy.sh/oauth/authorize";
pub const TOKEN_URL: &str = "https://osu.ppy.sh/oauth/token";

#[derive(Debug, Clone)]
pub struct ApiError {
    details: String,
}

impl ApiError {
    fn new(msg: &str) -> ApiError {
        ApiError {
            details: msg.to_string(),
        }
    }
}

impl Error for ApiError {
    fn description(&self) -> &str {
        &self.details
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl std::convert::From<ParseError> for ApiError {
    fn from(_error: ParseError) -> Self {
        ApiError::new(&_error.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum Scope {
    Bot,
    ChatWrite,
    ForumWrite,
    FriendsRead,
    Identify,
    Public,
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match *self {
                Scope::Bot => "bot",
                Scope::ChatWrite => "chat.write",
                Scope::ForumWrite => "forum.write",
                Scope::FriendsRead => "friends.read",
                Scope::Identify => "identify",
                Scope::Public => "public",
            }
        )
    }
}

impl std::convert::From<&Scope> for oauth2::Scope {
    fn from(s: &Scope) -> Self {
        Self::new(s.to_string())
    }
}

impl std::convert::From<Scope> for oauth2::Scope {
    fn from(s: Scope) -> Self {
        Self::new(s.to_string())
    }
}

pub struct OAuthIntermediateState {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_url: RedirectUrl,
    pub auth_url: oauth2::url::Url,
    pkce_verifier: oauth2::PkceCodeVerifier,
    csrf_token: oauth2::CsrfToken,
}

pub(crate) fn prepare_oauth_request(
    client_id: i32,
    client_secret: &str,
    redirect_url: &str,
    scopes: &[Scope],
) -> Result<OAuthIntermediateState, ApiError> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = ClientSecret::new(client_secret.to_owned());
    let redirect_url = RedirectUrl::new(redirect_url.to_owned())?;

    let client = BasicClient::new(
        client_id.clone(),
        Some(client_secret.clone()),
        AuthUrl::new(AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    )
    .set_redirect_uri(redirect_url.clone());

    let mut req = client.authorize_url(CsrfToken::new_random);
    req = req.add_scopes(scopes.iter().map(|s| s.into()));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    req = req.set_pkce_challenge(pkce_challenge);

    let (auth_url, csrf_token) = req.url();
    Ok(OAuthIntermediateState {
        client_id,
        client_secret,
        redirect_url,
        pkce_verifier,
        auth_url,
        csrf_token,
    })
}

pub fn exchange_code(
    state: OAuthIntermediateState,
    auth_code: &str,
    server_state: &str,
) -> Result<String, ApiError> {
    if state.csrf_token.secret().as_str() != server_state {
        Err(ApiError::new("Server returned a different CSRF token -- unable to recover (incorrectly setup client?)"))
    } else {
        let client = BasicClient::new(
            state.client_id,
            Some(state.client_secret),
            AuthUrl::new(AUTH_URL.to_string())?,
            Some(TokenUrl::new(TOKEN_URL.to_string())?),
        )
        .set_redirect_uri(state.redirect_url);

        let req = client
            .exchange_code(AuthorizationCode::new(auth_code.to_string()))
            .set_pkce_verifier(state.pkce_verifier);

        match req.request(http_client) {
            Ok(resp) => Ok(resp.access_token().secret().to_string()),
            Err(e) => Err(ApiError::new(&format!(
                "Failed to request a token from osu! API: {}",
                e
            ))),
        }
    }
}

// Block on listening on localhost:{port} until anything hits, then extract server code and state from the query string.
pub(crate) fn listen_for_code(redirect_url: &str, local_port: i16) -> (String, String) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", local_port))
        .unwrap_or_else(|e| panic!("Failed to listen on port {}: {}", local_port, e));
    let mut stream = listener.incoming().next().unwrap().unwrap();
    let buf_reader = BufReader::new(&mut stream);

    // "GET /?code=...&state=... HTTP/1.1"
    let http_method_call = buf_reader.lines().next().unwrap().unwrap();
    let path = http_method_call
        .split_ascii_whitespace()
        .find(|chunk| chunk.starts_with('/'))
        .unwrap_or_else(|| panic!("Malformed HTTP method call: {}", http_method_call));

    let status_line = "HTTP/1.1 200 OK";
    let contents =
        "<html><body>Server response fetched, now please head back to the console.<br/><span style='margin:20px;'>&mdash; osu-api library</span></body></html>";
    let length = contents.len();
    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");
    stream.write_all(response.as_bytes()).unwrap();

    let mut parsed_qs = std::collections::HashMap::<String, String>::new();
    let url = Url::parse(&format!("{}{}", redirect_url, path)).unwrap();
    url.query_pairs().for_each(|p| {
        parsed_qs.insert(p.0.to_string(), p.1.to_string());
    });

    (parsed_qs["code"].to_owned(), parsed_qs["state"].to_owned())
}
