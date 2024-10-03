use std::cell::OnceCell;

use axum::http::{header, HeaderName};
use serde::Deserialize;
use url::Url;
use worker::{send::SendWrapper, Env};

// ---------- SECRETS ----------

struct CachedSecret {
  pub id: &'static str,
  pub cell: OnceCell<String>
}

/// Adds all provided secret keys to the public `Secret` enum and
/// an array which is used for indexing and caching their values
macro_rules! secrets {
  (
    // number of secrets
    $count:expr,
    // comma delimited secret names (same as their values)
    $($name:ident),+
    // optional trailing comma
    $(,)?
  ) => {
    #[allow(non_camel_case_types)]
    pub enum Secret {
      // create an enum value for each secret
      $($name,)+
    }

    /// Array of all secrets.
    /// SendWrapper docs: https://docs.rs/worker/latest/worker/#send-helpers
    static SECRETS_ARRAY: [SendWrapper<CachedSecret>; $count] = [$(
      SendWrapper(
        CachedSecret {
          id: stringify!($name),
          cell: OnceCell::new()
        }
      ),
    )+];
  };
}

// Implicitly creates the public `Secret` enum and private
// `SECRETS_ARRAY`.
secrets!(
  9,
  CLIENT_SECRETS,
  WORKER_DOMAIN,
  JWK_PRIVATE,
  JWK_PUBLIC,
  GOOGLE_ADMIN_EMAIL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_SERVICEACCOUNT_KEY,
  GOOGLE_WORKSPACE_DOMAIN
);

// Converts a `Secret` enum value to a `SECRETS_ARRAY` index.
// This is fine since the `secrets!` macro guarantees the same
// ordering and number of entries for both variables.
impl Secret {
  fn as_index(self) -> usize {
    self as usize
  }
}

/// iterates all secrets and panics at "<no value>" entries
pub fn validate_secrets(env: &Env) {
  let mut errors = SECRETS_ARRAY.iter()
    .filter_map(|secret| {
      env.secret(secret.id)
        .err()
        .map(|e| e.to_string()) 
    }).peekable();

  assert!(
    errors.peek().is_none(),
    "{}",
    errors.collect::<Vec<_>>().join("\n")
  );
}

/// Get a cached secret
pub fn get_secret(env: &Env, id: Secret) -> &str {
  get_or_init(env, &SECRETS_ARRAY[id.as_index()])
}

fn get_or_init(
  env: &Env,
  secret: &'static SendWrapper<CachedSecret>
) -> &'static str {
  secret.cell.get_or_init(|| {
    env.secret(secret.id)
      // already validated by `validate_secrets`
      .unwrap()
      .as_ref()
      .as_string()
      // guaranteed to be string
      .unwrap()
  })
}

#[derive(Deserialize)]
pub struct ClientSecret {
  pub redirect_uris: Vec<Url>,
}

// ---------- CONSTANTS ----------

/// force var name to be the same as its string value
macro_rules! constant {
  ($name:ident) => {
    pub const $name: &str = stringify!($name);
  }
}

// KV

constant!(KV_AUTHORIZE_STATE);
constant!(KV_ACCESS_TOKEN_STATE);
constant!(KV_REFRESH_TOKEN_STATE);

// KV store for computed values shared by all workers
constant!(KV_CACHE);
constant!(KEY_PROVIDER_METADATA);
constant!(KEY_SERVICEACCOUNT_OAUTH_TOKEN);

// ---------- TOKEN HEADER ----------

pub const TOKEN_HEADER: [(HeaderName, &str); 2] = [
  (header::CACHE_CONTROL, "no-store"),
  (header::PRAGMA, "no-cache")
];