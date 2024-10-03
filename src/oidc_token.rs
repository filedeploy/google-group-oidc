use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use getrandom::getrandom;
use openidconnect::SubjectIdentifier;
use serde::Serialize;
use surrealdb_jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use worker::Env;

use crate::{consts::{get_secret, Secret}, handler_error::HandlerError};

// Source: https://openid.net/specs/openid-connect-core-1_0.html#IDToken
#[derive(Serialize)]
struct OidcToken<'a> {
  iss: &'a str,
  aud: &'a str,
  sub: SubjectIdentifier,
  exp: u64,
  iat: u64,
  nonce: &'a str,
  groups: Option<Vec<String>>
}
pub fn create_oidc_token(
  env: &Env,
  client_id: &str,
  client_nonce: &str,
  google_subject: SubjectIdentifier,
  issue_time: DateTime<Utc>,
  expiration: DateTime<Utc>,
  groups: Option<Vec<String>>
) -> Result<String, HandlerError> {
  let oidc_token = OidcToken {
    iss: get_secret(env, Secret::WORKER_DOMAIN),
    aud: client_id,
    sub: google_subject,
    // panic if these are negative
    iat: issue_time.timestamp().try_into().unwrap(),
    exp: expiration.timestamp().try_into().unwrap(),
    nonce: client_nonce,
    groups
  };

  // JWT encode it
  encode(
    &Header::new(Algorithm::RS256),
    &oidc_token,
    &EncodingKey::from_rsa_pem(
      get_secret(env, Secret::JWK_PRIVATE).as_bytes()
    ).map_err(HandlerError::JwtIdToken)?
  ).map_err(HandlerError::JwtIdToken)
}

pub fn new_token<const BYTES: usize>() -> String {
  let mut rand_buf = [0u8; BYTES];
  getrandom(&mut rand_buf).unwrap();
  URL_SAFE_NO_PAD.encode(rand_buf)
}
