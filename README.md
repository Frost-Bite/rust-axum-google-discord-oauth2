# What if you need a simple Axum OAuth authorization?

Here's another way to add OAuth2 to Axum. This code is a rewritten version of the Axum example found [here](https://github.com/tokio-rs/axum/tree/main/examples/oauth), but with the addition of Redis and multiple OAuth providers: Google and Discord. It uses the [OAuth2 crate](https://crates.io/crates/oauth2).

In the Nuxt folder, you'll find an example for frontend integration. It's similar to other frameworks. You need to deploy it on the same domain or share cookies across subdomains like `.example.com`.

# Features
- OAuth2 integration with Discord and Google.
- Redis-backed session management.
- CORS support.
- Axum for routing and request handling.

# Installation

Make sure you have the following installed:
- Rust
- Redis
- Cargo

Set the environment variables to configure the OAuth providers in the `.env` file. Use the `env-example` file.

Start the Redis server (default port 6379).
```bash
cargo run
```
In nuxt-example folder:
```bash
npm install
npm run dev
```
Instead of Nuxt, you can use routes:

## Available Routes
- `GET /auth/discord`: Initiates Discord OAuth2 login.
- `GET /auth/discord/authorized`: Handles Discord OAuth2 callback.
- `GET /auth/google`: Initiates Google OAuth2 login.
- `GET /auth/google/authorized`: Handles Google OAuth2 callback.
- `GET /protected`: Protected route that requires a valid session.
- `GET /logout`: Logs the user out and destroys the session.

# OAuth2 Flow
1. The user is redirected to the provider for authorization.
2. The provider returns an authorization code.
3. The server exchanges the code for an access token.
4. The user info is fetched and stored in the Redis session.

# Other Ways
[oauth_axum](https://crates.io/crates/oauth-axum) - wrapper of oauth2 lib, but it has all the provider configuration done, making it easy to implement in your Axum.

If you need more user identification and authorization handling, use the [Axum Login crate](https://crates.io/crates/axum-login). It's one of the simplest solutions and includes an example with OAuth2.

If you're up for a challenge, try the [Rust10x Web App Blueprint](https://github.com/rust10x/rust-web-app). There’s a YouTube video explaining how everything works. If you're tired of the bad design of JWT (which, unfortunately, is very popular), this option is for you.

[User Registration and Email Verification example](https://github.com/wpcodevo/rust-user-signup-forgot-password-email) - guide how to add a forgot/reset password feature in Axum.

[Axum, PostgreSQL, & Email Verification example](https://github.com/AarambhDevHub/rust-backend-axum) - some regional laws will require verification of collected emails. And as protection against bots.
