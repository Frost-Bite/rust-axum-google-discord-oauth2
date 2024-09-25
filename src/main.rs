use async_redis_session_v2::RedisSessionStore;
use anyhow::{Context, Result};
use async_session::{serde_json, Session, SessionStore};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue},
    response::{IntoResponse, Redirect, Response},
    routing::get,
    RequestPartsExt, Router,
};
use axum_extra::{headers, TypedHeader};
use http::{header::{AUTHORIZATION, CONTENT_TYPE}, request::Parts, Method, StatusCode};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use std::env;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use dotenv::dotenv;

static COOKIE_NAME: &str = "SESSION";

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = match RedisSessionStore::new("redis://127.0.0.1:6379/") {
        Ok(store) => store,
        Err(err) => {
            tracing::error!("Failed to create Redis session store: {:#}", err);
            return;
        }
    };

    let discord_client = match oauth_client("discord") {
        Ok(client) => DiscordOAuthClient(client),
        Err(err) => {
            tracing::error!("Failed to initialize Discord OAuth client: {:#?}", err);
            return;
        }
    };

    let google_client = match oauth_client("google") {
        Ok(client) => GoogleOAuthClient(client),
        Err(err) => {
            tracing::error!("Failed to initialize Google OAuth client: {:#?}", err);
            return;
        }
    };

    let app_state = AppState {
        store,
        discord_client,
        google_client,
    };

    let cors = CorsLayer::new()
        .allow_origin([
            "http://127.0.0.1:3000".parse::<HeaderValue>().unwrap(),
            "http://127.0.0.1:3005".parse::<HeaderValue>().unwrap(),
        ])
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_credentials(true);

        let app = Router::new()
        .route("/", get(index))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/discord/authorized", get(discord_login_authorized))
        .route("/auth/google", get(google_auth))
        .route("/auth/google/authorized", get(google_login_authorized))
        .route("/protected", get(protected))
        .route("/logout", get(logout))
        .layer(cors)
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    tracing::debug!(
        "listening on {}",
        listener
            .local_addr()
            .context("failed to return local address")
            .unwrap()
    );

    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct DiscordOAuthClient(BasicClient);

#[derive(Clone)]
struct GoogleOAuthClient(BasicClient);

#[derive(Clone)]
struct AppState {
    store: RedisSessionStore,
    discord_client: DiscordOAuthClient,
    google_client: GoogleOAuthClient,
}

impl FromRef<AppState> for RedisSessionStore {
    fn from_ref(state: &AppState) -> RedisSessionStore {
        state.store.clone()
    }
}

impl FromRef<AppState> for DiscordOAuthClient {
    fn from_ref(state: &AppState) -> DiscordOAuthClient {
        state.discord_client.clone()
    }
}

impl FromRef<AppState> for GoogleOAuthClient {
    fn from_ref(state: &AppState) -> GoogleOAuthClient {
        state.google_client.clone()
    }
}

fn oauth_client(provider: &str) -> Result<BasicClient, AppError> {
    match provider {
        "discord" => {
            let client_id = env::var("DISCORD_CLIENT_ID").context("Missing DISCORD_CLIENT_ID!")?;
            let client_secret = env::var("DISCORD_CLIENT_SECRET").context("Missing DISCORD_CLIENT_SECRET!")?;
            let redirect_url = env::var("DISCORD_REDIRECT_URL").unwrap_or_else(|_| "http://127.0.0.1:3000/auth/discord/authorized".to_string());

            let auth_url = AuthUrl::new("https://discord.com/api/oauth2/authorize?response_type=code".to_string())
                .context("Invalid Discord authorization endpoint URL")?;
            let token_url = TokenUrl::new("https://discord.com/api/oauth2/token".to_string())
                .context("Invalid Discord token endpoint URL")?;

            Ok(BasicClient::new(
                ClientId::new(client_id),
                Some(ClientSecret::new(client_secret)),
                auth_url,
                Some(token_url),
            ).set_redirect_uri(RedirectUrl::new(redirect_url).context("failed to create redirection URL")?))
        }
        "google" => {
            let client_id = env::var("GOOGLE_CLIENT_ID").context("Missing GOOGLE_CLIENT_ID!")?;
            let client_secret = env::var("GOOGLE_CLIENT_SECRET").context("Missing GOOGLE_CLIENT_SECRET!")?;
            let redirect_url = env::var("GOOGLE_REDIRECT_URL").unwrap_or_else(|_| "http://127.0.0.1:3000/auth/google/authorized".to_string());

            let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .context("Invalid Google authorization endpoint URL")?;
            let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
                .context("Invalid Google token endpoint URL")?;

            Ok(BasicClient::new(
                ClientId::new(client_id),
                Some(ClientSecret::new(client_secret)),
                auth_url,
                Some(token_url),
            ).set_redirect_uri(RedirectUrl::new(redirect_url).context("failed to create redirection URL")?))
        }
        _ => Err(AppError(anyhow::anyhow!("Unknown provider"))),
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: String,
    avatar: Option<String>,
    username: String,
    discriminator: String, // For Discord; blank for Google
    email: Option<String>,
}

async fn index(user: Option<User>) -> impl IntoResponse {
    match user {
        Some(u) => {
            let response_body = serde_json::json!({
                "username": u.username,
                "id": u.id,
                "discriminator": u.discriminator,
                "avatar": u.avatar,
                "email": u.email,
            });
            (StatusCode::OK, axum::Json(response_body))
        }
        None => {
            let response_body = serde_json::json!({
                "error": "User not logged in"
            });
            (StatusCode::UNAUTHORIZED, axum::Json(response_body))
        }
    }
}

async fn discord_auth(
    State(store): State<RedisSessionStore>,
    State(discord_client): State<DiscordOAuthClient>,
) -> impl IntoResponse {
    let oauth_client = discord_client.0.clone();

    let (auth_url, csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("identify".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .url();

    let mut session = Session::new();
    session.insert("csrf_token", csrf_token.secret()).unwrap();
    session.expire_in(Duration::from_secs(3600));

    match store.store_session(session).await {
        Ok(Some(cookie)) => {
            let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");
            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());
            (headers, Redirect::to(auth_url.as_ref())).into_response()
        }
        _ => {
            tracing::error!("Failed to store session in Redis");
            (StatusCode::INTERNAL_SERVER_ERROR, "Could not store session, check Redis server").into_response()
        }
    }
}

async fn google_auth(
    State(store): State<RedisSessionStore>,
    State(google_client): State<GoogleOAuthClient>,
) -> impl IntoResponse {
    let oauth_client = google_client.0.clone();

    let (auth_url, csrf_token) = oauth_client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.email".to_string()))
        .add_scope(Scope::new("https://www.googleapis.com/auth/userinfo.profile".to_string()))
        .url();

    let mut session = Session::new();
    session.insert("csrf_token", csrf_token.secret()).unwrap();
    session.expire_in(Duration::from_secs(3600));

    match store.store_session(session).await {
        Ok(Some(cookie)) => {
            let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");
            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());
            (headers, Redirect::to(auth_url.as_ref())).into_response()
        }
        _ => {
            tracing::error!("Failed to store session in Redis");
            (StatusCode::INTERNAL_SERVER_ERROR, "Could not store session, check Redis server").into_response()
        }
    }
}

// Valid user session required.
async fn protected(user: User) -> impl IntoResponse {
    format!("Welcome to the protected area :)\nHere's your info:\n{user:?}")
}

async fn logout(
    State(store): State<RedisSessionStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies
        .get(COOKIE_NAME)
        .context("unexpected error getting cookie name")?;

    let session = match store
        .load_session(cookie.to_string())
        .await
        .context("failed to load session")?
    {
        Some(s) => s,
        None => return Ok(Redirect::to("/")),
    };

    store
        .destroy_session(session)
        .await
        .context("failed to destroy session")?;

    Ok(Redirect::to("/"))
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn discord_login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<RedisSessionStore>,
    State(oauth_client): State<DiscordOAuthClient>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies.get(COOKIE_NAME).context("missing session cookie")?;
    let session = store.load_session(cookie.to_string()).await?.context("session not found")?;

    let csrf_token: Option<String> = session.get("csrf_token");
    if csrf_token.is_none() || csrf_token.unwrap() != query.state {
        return Err(AppError(anyhow::anyhow!("Invalid CSRF token")));
    }

    let token = oauth_client.0.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client).await.context("failed to exchange authorization code")?;

    let client = reqwest::Client::new();
    let user_data: User = client.get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send().await.context("failed to fetch user data")?
        .json().await.context("failed to deserialize user data")?;

    let mut session = Session::new();
    session.insert("user", &user_data).unwrap();
    session.expire_in(Duration::from_secs(60 * 60));

    let cookie = store.store_session(session).await?.unwrap();
    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((headers, Redirect::to("http://127.0.0.1:3005")))
}


async fn google_login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<RedisSessionStore>,
    State(oauth_client): State<GoogleOAuthClient>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    // Step 1: Retrieve the session cookie
    let cookie = cookies.get(COOKIE_NAME).context("missing session cookie")?;
    let session = store.load_session(cookie.to_string()).await?.context("session not found")?;

    // Step 2: Validate the CSRF token
    let csrf_token: Option<String> = session.get("csrf_token");
    if csrf_token.is_none() || csrf_token.unwrap() != query.state {
        return Err(AppError(anyhow::anyhow!("Invalid CSRF token")));
    }

    // Step 3: Attempt to exchange authorization code for an access token
    tracing::debug!("Attempting to exchange authorization code: {:?}", query.code);
    let result = oauth_client
        .0.exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await;

    // Step 4: Check the result of the token exchange
    match result {
        Ok(token) => {
            tracing::debug!("Received token: {:?}", token);

            // Step 5: Use the token to fetch user information from Google
            let client = reqwest::Client::new();
            let user_info = client.get("https://www.googleapis.com/oauth2/v1/userinfo")
                .bearer_auth(token.access_token().secret())
                .send().await.context("failed to fetch user data")?
                .json::<serde_json::Value>().await.context("failed to deserialize user data")?;

            tracing::debug!("Received user info: {:?}", user_info);

            // Step 6: Create a user object
            let user = User {
                id: user_info["id"].as_str().unwrap_or_default().to_string(),
                avatar: user_info["picture"].as_str().map(|s| s.to_string()),
                username: user_info["name"].as_str().unwrap_or_default().to_string(),
                discriminator: "".to_string(), // Google doesn't provide a discriminator
                email: Some(user_info["email"].as_str().unwrap_or_default().to_string()),
            };

            // Step 7: Store the user in session
            let mut session = Session::new();
            session.insert("user", &user).unwrap();
            session.expire_in(Duration::from_secs(60 * 60));

            let cookie = store.store_session(session).await?.unwrap();
            let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");

            let mut headers = HeaderMap::new();
            headers.insert(SET_COOKIE, cookie.parse().unwrap());

            Ok((headers, Redirect::to("http://127.0.0.1:3005")))
        }
        Err(err) => {
            tracing::error!("Failed to exchange authorization code: {:?}", err);
            Err(AppError(anyhow::anyhow!("Failed to exchange authorization code: {:?}", err)))
        }
    }
}

#[derive(Debug)]
struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::to("/auth/discord").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    RedisSessionStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = RedisSessionStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|_| AuthRedirect)?;

        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        match store.load_session(session_cookie.to_string()).await {
            Ok(Some(session)) => {
                if let Some(user) = session.get::<User>("user") {
                    Ok(user)
                } else {
                    Err(AuthRedirect)
                }
            }
            Ok(None) => Err(AuthRedirect),
            Err(err) => {
                tracing::error!("Failed to load session from Redis: {:#}", err);
                Err(AuthRedirect)
            }
        }
    }
}

#[derive(Debug)]
struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(error: E) -> Self {
        Self(error.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({
            "error": self.0.to_string(),
        });

        (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
    }
}
