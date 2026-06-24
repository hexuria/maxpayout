use leptos::config::get_configuration;
use leptos_wasi::executor::init_wasip3_spawner;
use leptos_wasi::prelude::Handler;
use wasip3::http::types::{ErrorCode, Request, Response};

use crate::app::{
    App, AwardPoints, GetActiveSessions, GetUserDashboardStatus, LoginPasskeyFinish,
    LoginPasskeyStart, LoginViaMagicLink, LoginWithPassword, Logout, RegisterPasskeyFinish,
    RegisterPasskeyFinishSignup, RegisterPasskeyStart, RegisterWithPassword, RequestMagicLink,
    RevokeOtherSessions, RevokeSession, SetReferralCookieSsr, shell,
};

struct LeptosServer;

impl wasip3::exports::http::handler::Guest for LeptosServer {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        // 1. Initialize host async task scheduling
        let _ = init_wasip3_spawner();

        let conf = get_configuration(None).unwrap();
        let leptos_options = conf.leptos_options;

        // Convert the WASI request to http::Request
        let req = wasip3::http_compat::http_from_wasi_request(request)?;

        // 2. Build and handle request natively
        let wasi_res = Handler::build(req)
            .await
            .map_err(|e| {
                eprintln!("Error building handler: {:?}", e);
                ErrorCode::InternalError(None)
            })?
            .static_files_handler("/pkg", serve_static_files)
            .with_server_fn_axum::<RequestMagicLink>()
            .with_server_fn_axum::<LoginViaMagicLink>()
            .with_server_fn_axum::<LoginWithPassword>()
            .with_server_fn_axum::<RegisterWithPassword>()
            .with_server_fn_axum::<SetReferralCookieSsr>()
            .with_server_fn_axum::<Logout>()
            .with_server_fn_axum::<GetUserDashboardStatus>()
            .with_server_fn_axum::<GetActiveSessions>()
            .with_server_fn_axum::<RevokeSession>()
            .with_server_fn_axum::<RevokeOtherSessions>()
            .with_server_fn_axum::<AwardPoints>()
            .with_server_fn_axum::<RegisterPasskeyStart>()
            .with_server_fn_axum::<RegisterPasskeyFinish>()
            .with_server_fn_axum::<LoginPasskeyStart>()
            .with_server_fn_axum::<LoginPasskeyFinish>()
            .with_server_fn_axum::<RegisterPasskeyFinishSignup>()
            .generate_routes(App)
            .handle_with_context(move || shell(leptos_options.clone()), || {})
            .await
            .map_err(|e| {
                eprintln!("Error handling request: {:?}", e);
                ErrorCode::InternalError(None)
            })?;

        Ok(wasi_res)
    }
}

fn serve_static_files(path: String) -> Option<leptos_wasi::response::Body> {
    use std::fs;
    let path = path.strip_prefix("/").unwrap_or(&path);
    // Wasmtime mounts site directory at root, so look at /path directly
    let file_path = format!("/{}", path);
    println!("serving static file: {}", file_path);

    if let Ok(bytes) = fs::read(&file_path) {
        Some(leptos_wasi::response::Body::Sync(bytes.into()))
    } else {
        println!("Could not read file at {}", file_path);
        None
    }
}

// Export the server for standard WASIp3 http trigger
wasip3::http::service::export!(LeptosServer);
