use axum::{extract::State, Json};
use serde_json::json;
use worker::Env;

use crate::consts::{get_secret, Secret};

// TODO: this doesn't need to be async
#[worker::send]
pub async fn jwks(State(env): State<Env>) -> Json<serde_json::Value> {
  let jwk_public: serde_json::Value = serde_json::from_str(
    get_secret(&env, Secret::JWK_PUBLIC)
  ).unwrap();

  Json(
    json!({
      "keys": [jwk_public]
    })
  )
}