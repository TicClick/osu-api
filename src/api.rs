use std::fmt;
use std::error::Error;

use oauth2::basic::BasicClient;
use oauth2::reqwest::http_client;
use oauth2::url::ParseError;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    TokenResponse, TokenUrl,
};

pub const AUTH_URL: &str = "https://osu.ppy.sh/oauth/authorize";
pub const TOKEN_URL: &str = "https://osu.ppy.sh/oauth/token";

#[derive(Debug, Clone)]
pub struct ApiError {
    details: String
}

impl ApiError {
    fn new(msg: &str) -> ApiError {
        ApiError{details: msg.to_string()}
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

pub struct OAuthIntermediateState {
    pub client_id: ClientId,
    pub client_secret: ClientSecret,
    pub redirect_url: RedirectUrl,
    pub auth_url: oauth2::url::Url,
    pkce_verifier: oauth2::PkceCodeVerifier,
    csrf_token: oauth2::CsrfToken,
}

pub fn request_grant(
    client_id: i32,
    client_secret: String,
    redirect_url: String,
    scopes: &[Scope],
) -> Result<OAuthIntermediateState, ApiError> {
    let client_id = ClientId::new(client_id.to_string());
    let client_secret = ClientSecret::new(client_secret);
    let redirect_url = RedirectUrl::new(redirect_url)?;

    let client = BasicClient::new(
        client_id.clone(),
        Some(client_secret.clone()),
        AuthUrl::new(AUTH_URL.to_string())?,
        Some(TokenUrl::new(TOKEN_URL.to_string())?),
    )
    .set_redirect_uri(redirect_url.clone());

    let mut req = client.authorize_url(CsrfToken::new_random);
    for scope in scopes.iter() {
        req = req.add_scope(oauth2::Scope::new(scope.to_string()));
    }
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    req = req.set_pkce_challenge(pkce_challenge);

    let (auth_url, csrf_token) = req.url();

    Ok(OAuthIntermediateState {
        client_id: client_id,
        client_secret: client_secret,
        redirect_url: redirect_url.clone(),
        pkce_verifier: pkce_verifier,
        auth_url: auth_url,
        csrf_token: csrf_token,
    })
}

pub fn exchange_code(
    state: OAuthIntermediateState,
    auth_code: String,
    server_state: String,
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
            .exchange_code(AuthorizationCode::new(auth_code))
            .set_pkce_verifier(state.pkce_verifier);

        match req.request(http_client) {
            Ok(resp) => Ok(resp.access_token().secret().to_string()),
            Err(e) => Err(ApiError::new(&format!("Failed to request a token from osu! api: {}", e))),
        }
    }
}
