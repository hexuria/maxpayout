use std::collections::HashMap;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration as StdDuration;

use base64::Engine;
use jwt_simple::prelude::*;
use rand::{Rng, distributions::Alphanumeric};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KEY_ID: &str = "fake-oauth-key";
const TENANT_ID: &str = "fake-tenant";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Provider {
    Google,
    Apple,
    Microsoft,
    Facebook,
}

impl Provider {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "google" => Some(Self::Google),
            "apple" => Some(Self::Apple),
            "microsoft" | "ms" | "azure" => Some(Self::Microsoft),
            "facebook" | "meta" => Some(Self::Facebook),
            _ => None,
        }
    }

    fn infer_from_client_id(client_id: &str) -> Option<Self> {
        ["google", "apple", "microsoft", "facebook"]
            .iter()
            .find_map(|provider| {
                if client_id.to_lowercase().contains(provider) {
                    Self::parse(provider)
                } else {
                    None
                }
            })
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Apple => "apple",
            Self::Microsoft => "microsoft",
            Self::Facebook => "facebook",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::Apple => "Apple",
            Self::Microsoft => "Microsoft",
            Self::Facebook => "Facebook",
        }
    }

    fn user_id(self) -> String {
        format!("fake-{}-user-1", self.slug())
    }

    fn email(self) -> String {
        format!("{}-user@example.test", self.slug())
    }

    fn issuer(self, issuer_base: &str) -> String {
        match self {
            Self::Microsoft => format!("{issuer_base}/microsoft/{TENANT_ID}/v2.0"),
            _ => format!("{issuer_base}/{}", self.slug()),
        }
    }
}

#[derive(Clone, Debug)]
struct IssuedCode {
    provider: Provider,
    client_id: String,
    redirect_uri: String,
    nonce: String,
    code_challenge: String,
}

struct AppState {
    issuer_base: String,
    key_pair: RS256KeyPair,
    issued_codes: Mutex<HashMap<String, IssuedCode>>,
}

struct HttpRequest {
    method: String,
    path: String,
    query: HashMap<String, String>,
    body: Vec<u8>,
}

struct HttpResponse {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn main() -> Result<(), String> {
    let config = ServerConfig::from_args(env::args().skip(1))?;
    let issuer_base = format!("http://{}:{}", config.host, config.port);
    let listener = TcpListener::bind((config.host.as_str(), config.port))
        .map_err(|e| format!("Failed to bind fake OAuth provider: {e}"))?;

    let state = Arc::new(AppState {
        issuer_base: issuer_base.clone(),
        key_pair: RS256KeyPair::generate(2048)
            .map_err(|e| format!("Failed to generate fake RSA key: {e}"))?
            .with_key_id(KEY_ID),
        issued_codes: Mutex::new(HashMap::new()),
    });

    print_startup_env(&issuer_base);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(err) = handle_connection(stream, state) {
                        eprintln!("fake-oauth-provider request error: {err}");
                    }
                });
            }
            Err(err) => eprintln!("fake-oauth-provider accept error: {err}"),
        }
    }

    Ok(())
}

#[derive(Clone, Debug)]
struct ServerConfig {
    host: String,
    port: u16,
}

impl ServerConfig {
    fn from_args<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut host = "127.0.0.1".to_string();
        let mut port = 9001;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--host" => {
                    host = args
                        .next()
                        .ok_or_else(|| "--host requires a value".to_string())?;
                }
                "--port" => {
                    let value = args
                        .next()
                        .ok_or_else(|| "--port requires a value".to_string())?;
                    port = value
                        .parse()
                        .map_err(|_| format!("Invalid --port value: {value}"))?;
                }
                "--help" | "-h" => {
                    println!("Usage: fake-oauth-provider [--host 127.0.0.1] [--port 9001]");
                    std::process::exit(0);
                }
                other => return Err(format!("Unknown argument: {other}")),
            }
        }

        Ok(Self { host, port })
    }
}

fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) -> Result<(), String> {
    stream
        .set_read_timeout(Some(StdDuration::from_secs(5)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let req = read_request(&mut stream)?;
    let res = route_request(req, &state);
    write_response(&mut stream, res)
}

fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|e| format!("Failed to read request: {e}"))?;
        if read == 0 {
            return Err("Connection closed before request headers".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = find_header_end(&buffer) {
            break index;
        }
        if buffer.len() > 64 * 1024 {
            return Err("Request headers are too large".to_string());
        }
    };

    let header_text = std::str::from_utf8(&buffer[..header_end])
        .map_err(|e| format!("Request headers are not UTF-8: {e}"))?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "Request line missing".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "Request method missing".to_string())?
        .to_string();
    let target = request_parts
        .next()
        .ok_or_else(|| "Request target missing".to_string())?;
    let (path, query) = split_target(target);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    let mut body = buffer[body_start..].to_vec();
    while body.len() < content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|e| format!("Failed to read request body: {e}"))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    Ok(HttpRequest {
        method,
        path,
        query,
        body,
    })
}

fn route_request(req: HttpRequest, state: &AppState) -> HttpResponse {
    if req.method == "OPTIONS" {
        return HttpResponse {
            status: "204 No Content",
            headers: cors_headers(),
            body: Vec::new(),
        };
    }

    let route = match parse_route(&req) {
        Ok(route) => route,
        Err(err) => return error_response("400 Bad Request", &err),
    };

    match route.endpoint.as_str() {
        "healthz" => json_response(json!({"ok": true})),
        "authorize" => authorize_response(route.provider, &req, state),
        "token" => token_response(route.provider, &req, state),
        "jwks" => jwks_response(state),
        "me" => me_response(route.provider),
        "" => landing_response(state),
        _ => error_response("404 Not Found", "Unknown fake OAuth endpoint"),
    }
}

struct Route {
    provider: Provider,
    endpoint: String,
}

fn parse_route(req: &HttpRequest) -> Result<Route, String> {
    let segments = req
        .path
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();

    if segments.is_empty() {
        return Ok(Route {
            provider: Provider::Google,
            endpoint: String::new(),
        });
    }
    if segments[0] == "healthz" {
        return Ok(Route {
            provider: Provider::Google,
            endpoint: "healthz".to_string(),
        });
    }
    if let Some(provider) = Provider::parse(segments[0]) {
        let endpoint = segments
            .get(1)
            .ok_or_else(|| "Provider route requires an endpoint".to_string())?
            .to_string();
        return Ok(Route { provider, endpoint });
    }

    let provider = req
        .query
        .get("provider")
        .and_then(|value| Provider::parse(value))
        .or_else(|| {
            req.query
                .get("client_id")
                .and_then(|client_id| Provider::infer_from_client_id(client_id))
        })
        .unwrap_or(Provider::Google);

    Ok(Route {
        provider,
        endpoint: segments[0].to_string(),
    })
}

fn authorize_response(provider: Provider, req: &HttpRequest, state: &AppState) -> HttpResponse {
    if req.method != "GET" {
        return error_response("405 Method Not Allowed", "Use GET for /authorize");
    }

    let Some(client_id) = req.query.get("client_id").cloned() else {
        return error_response("400 Bad Request", "authorize request missing client_id");
    };
    let Some(redirect_uri) = req.query.get("redirect_uri").cloned() else {
        return error_response("400 Bad Request", "authorize request missing redirect_uri");
    };
    let Some(state_token) = req.query.get("state").cloned() else {
        return error_response("400 Bad Request", "authorize request missing state");
    };
    let Some(nonce) = req.query.get("nonce").cloned() else {
        return error_response("400 Bad Request", "authorize request missing nonce");
    };
    let Some(code_challenge) = req.query.get("code_challenge").cloned() else {
        return error_response(
            "400 Bad Request",
            "authorize request missing code_challenge",
        );
    };

    let code = random_token(24);
    let issued = IssuedCode {
        provider,
        client_id,
        redirect_uri: redirect_uri.clone(),
        nonce,
        code_challenge,
    };
    match state.issued_codes.lock() {
        Ok(mut codes) => {
            codes.insert(code.clone(), issued);
        }
        Err(_) => return error_response("500 Internal Server Error", "code store lock poisoned"),
    }

    redirect_response(&append_query(
        &redirect_uri,
        &[
            ("code", code.as_str()),
            ("state", state_token.as_str()),
            ("provider", provider.slug()),
        ],
    ))
}

fn token_response(route_provider: Provider, req: &HttpRequest, state: &AppState) -> HttpResponse {
    if req.method != "POST" {
        return error_response("405 Method Not Allowed", "Use POST for /token");
    }

    let body = match std::str::from_utf8(&req.body) {
        Ok(body) => body,
        Err(_) => return error_response("400 Bad Request", "token body is not UTF-8"),
    };
    let form = parse_pairs(body);
    let Some(code) = form.get("code") else {
        return error_response("400 Bad Request", "token request missing code");
    };
    let Some(code_verifier) = form.get("code_verifier") else {
        return error_response("400 Bad Request", "token request missing code_verifier");
    };
    let Some(client_id) = form.get("client_id") else {
        return error_response("400 Bad Request", "token request missing client_id");
    };

    let issued = match state.issued_codes.lock() {
        Ok(mut codes) => match codes.remove(code) {
            Some(issued) => issued,
            None => return oauth_error("invalid_grant", "unknown or already-used code"),
        },
        Err(_) => return error_response("500 Internal Server Error", "code store lock poisoned"),
    };

    if issued.provider != route_provider {
        return oauth_error("invalid_grant", "code was issued for another provider");
    }
    if &issued.client_id != client_id {
        return oauth_error("invalid_client", "client_id does not match issued code");
    }
    if !constant_time_eq(&pkce_challenge(code_verifier), &issued.code_challenge) {
        return oauth_error(
            "invalid_grant",
            "PKCE code_verifier does not match code_challenge",
        );
    }
    if form.get("redirect_uri") != Some(&issued.redirect_uri) {
        return oauth_error("invalid_grant", "redirect_uri does not match issued code");
    }

    if issued.provider == Provider::Facebook {
        return json_response(json!({
            "token_type": "Bearer",
            "expires_in": 600,
            "access_token": format!("fake-facebook-access-{}", random_token(12))
        }));
    }

    let token = match sign_id_token(state, &issued) {
        Ok(token) => token,
        Err(err) => return error_response("500 Internal Server Error", &err),
    };

    json_response(json!({
        "token_type": "Bearer",
        "expires_in": 600,
        "id_token": token
    }))
}

fn sign_id_token(state: &AppState, issued: &IssuedCode) -> Result<String, String> {
    let provider = issued.provider;
    let mut custom = json!({
        "email": provider.email(),
        "email_verified": true,
        "name": format!("Fake {} User", provider.label()),
        "preferred_username": provider.email()
    });

    if provider == Provider::Microsoft {
        custom["tid"] = Value::String(TENANT_ID.to_string());
    }

    let claims = Claims::with_custom_claims(custom, jwt_simple::prelude::Duration::from_mins(10))
        .with_issuer(provider.issuer(&state.issuer_base))
        .with_audience(issued.client_id.clone())
        .with_subject(provider.user_id())
        .with_nonce(issued.nonce.clone());

    state
        .key_pair
        .sign(claims)
        .map_err(|e| format!("Failed to sign id_token: {e}"))
}

fn jwks_response(state: &AppState) -> HttpResponse {
    let components = state.key_pair.public_key().to_components();
    json_response(json!({
        "keys": [{
            "kty": "RSA",
            "kid": KEY_ID,
            "alg": "RS256",
            "use": "sig",
            "n": base64_url_encode(&components.n),
            "e": base64_url_encode(&components.e)
        }]
    }))
}

fn me_response(provider: Provider) -> HttpResponse {
    match provider {
        Provider::Facebook => json_response(json!({
            "id": provider.user_id(),
            "email": provider.email(),
            "name": format!("Fake {} User", provider.label())
        })),
        Provider::Microsoft => json_response(json!({
            "id": provider.user_id(),
            "mail": provider.email(),
            "userPrincipalName": provider.email(),
            "displayName": format!("Fake {} User", provider.label())
        })),
        _ => json_response(json!({
            "sub": provider.user_id(),
            "email": provider.email(),
            "email_verified": true,
            "name": format!("Fake {} User", provider.label())
        })),
    }
}

fn landing_response(state: &AppState) -> HttpResponse {
    let body = format!(
        "Fake OAuth provider is running at {}\n\nEndpoints:\n  /{{provider}}/authorize\n  /{{provider}}/token\n  /{{provider}}/jwks\n  /{{provider}}/me\n\nProviders: google, apple, microsoft, facebook\n",
        state.issuer_base
    );
    text_response("200 OK", &body)
}

fn split_target(target: &str) -> (String, HashMap<String, String>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path.to_string(), parse_pairs(query))
}

fn parse_pairs(input: &str) -> HashMap<String, String> {
    input
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Some((decode_component(key)?, decode_component(value)?))
        })
        .collect()
}

fn decode_component(value: &str) -> Option<String> {
    urlencoding::decode(value)
        .ok()
        .map(|value| value.into_owned())
}

fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let separator = if base.contains('?') { '&' } else { '?' };
    format!("{base}{separator}{}", encode_params(params))
}

fn encode_params(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", key, urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn pkce_challenge(verifier: &str) -> String {
    base64_url_encode(&Sha256::digest(verifier.as_bytes()))
}

fn base64_url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn redirect_response(location: &str) -> HttpResponse {
    HttpResponse {
        status: "302 Found",
        headers: vec![("Location".to_string(), location.to_string())],
        body: format!("Redirecting to {location}\n").into_bytes(),
    }
}

fn json_response(value: Value) -> HttpResponse {
    let body = serde_json::to_vec_pretty(&value).unwrap_or_else(|_| b"{}".to_vec());
    HttpResponse {
        status: "200 OK",
        headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        body,
    }
}

fn oauth_error(error: &str, description: &str) -> HttpResponse {
    let mut response = json_response(json!({
        "error": error,
        "error_description": description
    }));
    response.status = "400 Bad Request";
    response
}

fn error_response(status: &'static str, message: &str) -> HttpResponse {
    text_response(status, &format!("{message}\n"))
}

fn text_response(status: &'static str, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )],
        body: body.as_bytes().to_vec(),
    }
}

fn cors_headers() -> Vec<(String, String)> {
    vec![
        ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
        (
            "Access-Control-Allow-Methods".to_string(),
            "GET,POST,OPTIONS".to_string(),
        ),
        (
            "Access-Control-Allow-Headers".to_string(),
            "content-type,authorization".to_string(),
        ),
    ]
}

fn write_response(stream: &mut TcpStream, mut res: HttpResponse) -> Result<(), String> {
    let mut headers = cors_headers();
    headers.append(&mut res.headers);
    headers.push(("Content-Length".to_string(), res.body.len().to_string()));
    headers.push(("Connection".to_string(), "close".to_string()));

    let mut raw = format!("HTTP/1.1 {}\r\n", res.status).into_bytes();
    for (name, value) in headers {
        raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(&res.body);

    stream
        .write_all(&raw)
        .map_err(|e| format!("Failed to write response: {e}"))
}

fn print_startup_env(issuer_base: &str) {
    println!("Fake OAuth provider listening at {issuer_base}");
    println!();
    println!("Use fake credentials such as:");
    println!("  GOOGLE_CLIENT_ID=google-client");
    println!("  GOOGLE_CLIENT_SECRET=google-secret");
    println!("  APPLE_CLIENT_ID=apple-client");
    println!("  MICROSOFT_CLIENT_ID=microsoft-client");
    println!("  MICROSOFT_CLIENT_SECRET=microsoft-secret");
    println!("  FACEBOOK_CLIENT_ID=facebook-client");
    println!("  FACEBOOK_CLIENT_SECRET=facebook-secret");
    println!();
    println!("Endpoint overrides:");
    for provider in [
        Provider::Google,
        Provider::Apple,
        Provider::Microsoft,
        Provider::Facebook,
    ] {
        let prefix = provider.slug().to_uppercase();
        println!(
            "  OAUTH_{prefix}_AUTH_URL={issuer_base}/{}/authorize",
            provider.slug()
        );
        println!(
            "  OAUTH_{prefix}_TOKEN_URL={issuer_base}/{}/token",
            provider.slug()
        );
        if provider == Provider::Facebook {
            println!("  OAUTH_{prefix}_PROFILE_URL={issuer_base}/facebook/me?fields=id,email,name");
        } else {
            println!(
                "  OAUTH_{prefix}_JWKS_URL={issuer_base}/{}/jwks",
                provider.slug()
            );
            if provider == Provider::Microsoft {
                println!("  OAUTH_{prefix}_ISSUER={issuer_base}/microsoft/{{tenantid}}/v2.0");
            } else {
                println!("  OAUTH_{prefix}_ISSUER={issuer_base}/{}", provider.slug());
            }
        }
        println!();
    }
}
