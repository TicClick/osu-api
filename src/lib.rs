pub mod api;

use reqwest::{header, blocking};

pub fn new(raw_token: String) -> blocking::Client {
    let mut headers = header::HeaderMap::new();
    let mut token = String::from("Bearer ");
    token.push_str(raw_token.as_str());

    let mut auth = header::HeaderValue::from_str(token.as_str()).unwrap();
    auth.set_sensitive(true);
    headers.insert(header::AUTHORIZATION, auth);

    blocking::Client::builder()
        .default_headers(headers)
        .build().unwrap()
}
