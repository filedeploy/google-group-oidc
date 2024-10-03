use std::io;

use chrono::Duration;
use openidconnect::{core::{CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse, CoreJwsSigningAlgorithm, CoreProviderMetadata}, AuthorizationCode, JsonWebKeySet, Nonce, RefreshToken};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;
use worker::{kv::KvStore, Env};

use crate::{consts::KV_REFRESH_TOKEN_STATE, handler_error::HandlerError};

#[derive(Serialize, Deserialize)]
pub struct GenericAuthorizeState<S, U, N> {
  pub client_id: S,
  pub client_redirect: U,
  pub client_state: S,
  pub client_nonce: S,
  pub google_nonce: N,
  pub groups_scope: bool
}
/// Struct for storing both the client's authorization state
/// and Google's authorization state between worker requests.
pub type AuthorizeState = GenericAuthorizeState<
  String,
  Url,
  Nonce
>;
/// borrowed version of AuthorizeState to avoid clones
pub type AuthorizeStateRef<'a> = GenericAuthorizeState<
  &'a str,
  &'a Url,
  &'a Nonce
>;

#[derive(Serialize, Deserialize)]
pub struct GenericCommonTokenState<S, N> {
  pub client_id: S,
  pub client_nonce: S,
  pub google_nonce: N,
  pub groups_scope: bool
}
/// Struct for storing both the client's session state
/// and Google's session state between worker requests.
pub type CommonTokenState = GenericCommonTokenState<
  String,
  Nonce
>;
/// borrowed version of CommonTokenState to avoid clones
pub type CommonTokenStateRef<'a> = GenericCommonTokenState<
  &'a str,
  &'a Nonce
>;

// ---------- ACCESS TOKEN STATE ----------

#[derive(Serialize, Deserialize)]
pub struct GenericAccessTokenState<C, U, A> {
  pub common: C,
  pub client_redirect: U,
  pub google_code: A
}
/// Struct for storing both the client and Google's
/// access token state between worker requests.
pub type AccessTokenState = GenericAccessTokenState<
  CommonTokenState,
  Url,
  AuthorizationCode
>;
/// borrowed version of AccessTokenState to avoid clones
pub type AccessTokenStateRef<'a> = GenericAccessTokenState<
  CommonTokenStateRef<'a>,
  &'a Url,
  &'a AuthorizationCode
>;

// ---------- REFRESH TOKEN STATE ----------

/// Struct for storing both the client and Google's
/// refresh token state between worker requests.
#[derive(Serialize, Deserialize)]
pub struct RefreshTokenState {
  pub common: CommonTokenState,
  pub google_refresh: RefreshToken
}

/// Store RefreshTokenState in a KV store keyed by
/// the client's refresh token
pub async fn store_refresh_token_state(
  env: &Env,
  client_refresh_token: &str,
  state: &RefreshTokenState
) -> Result<(), HandlerError> {
  kv_put(
    &KvStore::from_this(env, KV_REFRESH_TOKEN_STATE)?,
    // key it by the client's refresh token
    client_refresh_token,
    state,
    // Google refresh tokens expire after one year
    Duration::days(364)
  ).await
}

// ---------- PROVIDER METADATA ----------

type CoreJwkSet = JsonWebKeySet<
  CoreJwsSigningAlgorithm,
  CoreJsonWebKeyType,
  CoreJsonWebKeyUse,
  CoreJsonWebKey
>;

#[derive(Serialize, Deserialize)]
pub struct GenericStoredProviderMetadata<CP, CJ> {
  pub metadata: CP,
  pub jwks: CJ
}
// ProviderMetadata intentionally skips serializing jwks', (https://github.com/ramosbugs/openidconnect-rs/blob/052f4a7234f9df9e1510cf6e49c8a45b0bf0d941/src/discovery/mod.rs#L65)
// so store them alongside.
pub type StoredProviderMetadata = GenericStoredProviderMetadata<
  CoreProviderMetadata,
  CoreJwkSet
>;
/// borrowed version of StoredProviderMetadata to avoid clones
pub type StoredProviderMetadataRef<'a> = GenericStoredProviderMetadata<
  &'a CoreProviderMetadata,
  &'a CoreJwkSet
>;

// ---------- KV ----------

pub async fn kv_get<D: DeserializeOwned>(
  kv: &KvStore,
  key: &str
) -> Result<Option<D>, HandlerError> {
  Ok(
    match kv.get(key)
      .bytes()
      .await? {
        Some(bytes) => cbor_deserialize(&bytes)?,
        None => None,
      }
  )
}

pub async fn kv_put<S: Serialize>(
  kv: &KvStore,
  key: &str,
  value: &S,
  ttl: Duration
) -> Result<(), HandlerError> {
  Ok(
    kv.put_bytes(
      key,
      &cbor_serialize(value)?
    )?.expiration_ttl(
      // panic on overflow
      ttl.num_seconds()
        .try_into()
        .unwrap()
    ).execute()
    .await?
  )
}

// ---------- CBOR ----------

fn cbor_serialize<T: Serialize>(data: &T) -> Result<Vec<u8>, ciborium::ser::Error<io::Error>> {
  let mut buffer = Vec::new();
  ciborium::into_writer(data, &mut buffer)?;
  Ok(buffer)
}

fn cbor_deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ciborium::de::Error<io::Error>> {
  ciborium::from_reader(bytes)
}