use chrono::{Duration, Utc};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use surrealdb_jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use url::Url;
use worker::{console_error, kv::KvStore, Env};

use crate::{consts::{get_secret, Secret, KEY_SERVICEACCOUNT_OAUTH_TOKEN, KV_CACHE}, handler_error::HandlerError, state::{kv_get, kv_put}};

#[derive(Deserialize)]
struct ServiceAccount {
  client_email: String,
  private_key: String
}

#[derive(Serialize, Deserialize)]
struct Claims<'a> {
  iss: &'a str,
  sub: &'a str,
  scope: &'a str,
  aud: &'a str,
  exp: i64,
  iat: i64
}

#[derive(Deserialize)]
struct TokenResponse {
  access_token: String
}

// Spec: https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_member_groups
#[derive(Deserialize)]
struct GroupsApiResponse {
  groups: Vec<GoogleGroup>
}
#[derive(Deserialize)]
struct GoogleGroup {
  email: String
}

/// Returns the names of all groups belonging to `domain` that `user_email` is a member of.
/// Note: this returns the group email name(s) (<group_name>@<domain>), not the group title.
/// Google Group titles are not guaranteed unique.
pub async fn get_user_groups(
  env: &Env,
  user_email: &str
) -> Result<Vec<String>, HandlerError> {
  let workspace_domain = get_secret(env, Secret::GOOGLE_WORKSPACE_DOMAIN);

  let client = Client::new();

  let access_token = get_access_token(env, &client).await?;

  // Source: https://developers.google.com/admin-sdk/directory/v1/guides/manage-groups#get_all_member_groups
  let url = Url::parse_with_params(
      "https://admin.googleapis.com/admin/directory/v1/groups",
      &[("userKey", user_email)]
    )
    // function doesn't validate params + valid static url
    .unwrap();

  let GroupsApiResponse { groups } = client.get(url)
    .bearer_auth(&access_token)
    .send()
    .await
    .map_err(HandlerError::GroupsAdminApi)?
    .json()
    .await
    .map_err(HandlerError::GroupsAdminApi)?;

  // Use the section before the email as the group name.
  // The `name` parameter itself is not guaranteed unique.
  Ok(
    groups.into_iter()
      .filter_map(|g| {
        let Some((name, domain)) = g.email.split_once('@') else {
          // Nonfatal
          // TODO: telemetry?
          console_error!(r#"Invalid group email: "{}""#, g.email);
          return None
        };

        // Only include groups from our workspace domain
        if domain == workspace_domain {
          return Some(name.to_string())
        }

        None
      })
      .collect()
  )
}

/// Source: https://developers.google.com/identity/protocols/oauth2/service-account#httprest
async fn get_access_token(
  env: &Env,
  client: &Client
) -> Result<String, HandlerError> {
  let admin_email = get_secret(env, Secret::GOOGLE_ADMIN_EMAIL);

  let kv = KvStore::from_this(env, KV_CACHE)?;
  
  if let Some(token) = kv_get(&kv, KEY_SERVICEACCOUNT_OAUTH_TOKEN).await? {
    return Ok(token)
  }

  // get a new token from oauth2.googleapis.com

  let ServiceAccount {
    client_email,
    private_key
  } = serde_json::from_str(
    get_secret(env, Secret::GOOGLE_SERVICEACCOUNT_KEY)
  )?;

  let token_ttl = Duration::hours(1);

  let now = Utc::now();
  let claims = Claims {
    iss: &client_email,
    // admin user the serviceaccount impersonates
    sub: admin_email,
    scope: "https://www.googleapis.com/auth/admin.directory.group.readonly",
    aud: "https://oauth2.googleapis.com/token",
    exp: (now + token_ttl).timestamp(),
    iat: now.timestamp(),
  };

  let jwt = encode(
    &Header::new(Algorithm::RS256),
    &claims,
    &EncodingKey::from_rsa_pem(private_key.as_bytes())
      .map_err(HandlerError::JwtGroupsOauth)?
  ).map_err(HandlerError::JwtGroupsOauth)?;

  let TokenResponse { access_token } = client
    .post("https://oauth2.googleapis.com/token")
    .form(&[
      ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
      ("assertion", &jwt),
    ])
    .send()
    .await
    .map_err(HandlerError::GroupsOauth)?
    .json()
    .await
    .map_err(HandlerError::GroupsOauth)?;

  // cache it
  kv_put(
    &kv,
    KEY_SERVICEACCOUNT_OAUTH_TOKEN,
    &access_token,
    token_ttl - Duration::minutes(1)
  ).await?;

  Ok(access_token)
}