use std::io;

use openidconnect::{core::CoreRequestTokenError, reqwest::AsyncHttpClientError, ClaimsVerificationError, DiscoveryError};
use surrealdb_jsonwebtoken::errors::Error as JwtError;
use worker::{kv::KvError, send::SendWrapper};

use crate::endpoints::{authorize_error::ErrorParams as AuthErrorParams, token_error::{TokenErrorResponse}};

// TODO: no Ball Of Mud errors (https://www.lpalmieri.com/posts/error-handling-rust/#avoid-ball-of-mud-error-enums)
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub enum HandlerError {
  // Storage
  Kv(SendWrapper<KvError>),
  CborSerialize(#[from] ciborium::de::Error<io::Error>),
  CborDeserialize(#[from] ciborium::ser::Error<io::Error>),
  #[error(r#"Missing entry "{}" from store "{}""#, .key, .kv_name)]
  KvMissing {
    kv_name: &'static str,
    key: String
  },
  // Parse JSON secret
  JsonDeserialize(#[from] serde_json::Error),
  // OIDC Client
  Discovery(#[from] DiscoveryError<AsyncHttpClientError>),
  ParseUrl(#[from] url::ParseError),
  GoogleToken(#[from] CoreRequestTokenError<AsyncHttpClientError>),
  #[error("Google Oauth response did not contain an id_token.")]
  MissingIdToken,
  InvalidClaims(#[from] ClaimsVerificationError),
  #[error("Google Oauth response did not include an email claim.")]
  MissingEmailClaim,
  // OIDC Server errors
  Authorize(AuthErrorParams),
  Token(#[from] TokenErrorResponse),
  // Groups (Google Admin SDK API)
  GroupsOauth(reqwest::Error),
  GroupsAdminApi(reqwest::Error),
  // JWT
  JwtIdToken(JwtError),
  JwtGroupsOauth(JwtError)
}

/// Convert KvError to StorageError
impl From<KvError> for HandlerError {
  fn from(err: KvError) -> Self {
    HandlerError::Kv(SendWrapper::new(err))
  }
}