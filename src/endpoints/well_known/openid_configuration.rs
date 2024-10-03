use axum::{extract::State, Json};
use serde_json::json;
use worker::Env;

use crate::consts::{get_secret, Secret};

// TODO: this doesn't need to be async
#[worker::send]
pub async fn openid_configuration(State(env): State<Env>) -> Json<serde_json::Value> {
  let domain = get_secret(&env, Secret::WORKER_DOMAIN);

  // Sources:
  //   https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
  //   https://accounts.google.com/.well-known/openid-configuration
  Json(
    json!({
      "issuer": domain,
      "authorization_endpoint": format!("{domain}/authorize"),
      "token_endpoint": format!("{domain}/token"),
      "jwks_uri":	format!("{domain}/jwks"),
      "response_types_supported": [
        "code",
        // // TODO
        // "token",
        // "id_token",
        // "code token",
        // "code id_token",
        // "token id_token",
        // "code token id_token",
        "none"
      ],
      "subject_types_supported": [
        "public"
      ],
      "id_token_signing_alg_values_supported": [
        "RS256"
      ],
      "scopes_supported": [
        "openid",
        "email",
      ],
      "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic"
      ],
      "claims_supported": [
        "aud",
        "email",
        "exp",
        "groups",
        "iat",
        "iss",
        "sub"
      ],
      "code_challenge_methods_supported": [
        "plain",
        "S256"
      ],
      "grant_types_supported": [
        "authorization_code",
        "refresh_token"
      ]
    })  
  )
}