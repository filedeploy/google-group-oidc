mod consts;
mod endpoints;
mod handler_error;
mod google;
mod groups;
mod oidc_token;
mod scope;
mod state;

use consts::validate_secrets;
use endpoints::{authorize, callback, jwks, token, well_known};
use axum::{body::Body, http::Response, routing::{get, post}, Router};
use tower_service::Service;
use worker::{event, Context, Env, HttpRequest};

// Program entrypoint. Essentially the `main` function.
#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _: Context) -> worker::Result<Response<Body>> {
  console_error_panic_hook::set_once();

  // panic on missing secrets
  validate_secrets(&env);

  Ok(
    // Routes are in the order they'll be hit during the the auth flow.
    Router::new()
      // Source: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
      .route("/.well-known/openid-configuration", get(well_known::openid_configuration))
      .route("/authorize", get(authorize).post(authorize))
      .route("/callback", get(callback))
      .route("/token", post(token))
      .route("/jwks", get(jwks))
      .with_state(env)
      .call(req)
      .await?
  )
}