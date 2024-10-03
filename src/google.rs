use chrono::{DateTime, Duration, Utc};
use openidconnect::{core::{CoreClient, CoreProviderMetadata, CoreRequestTokenError, CoreResponseType, CoreTokenResponse}, reqwest::{async_http_client, AsyncHttpClientError}, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndUserEmail, IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl, RefreshToken, RequestTokenError::ServerResponse, Scope, SubjectIdentifier};
use url::Url;
use worker::{kv::KvStore, Env};

use crate::{consts::{get_secret, Secret, KEY_PROVIDER_METADATA, KV_CACHE}, endpoints::token_error::TokenErrorResponse, handler_error::HandlerError, state::{kv_get, kv_put, StoredProviderMetadata, StoredProviderMetadataRef}};

/// Retrieve our cached and serialized Google OIDC provider
/// metadata, or create it if it does not exist.
async fn get_provider_metadata(env: &Env) -> Result<CoreProviderMetadata, HandlerError> {
  let kv = KvStore::from_this(env, KV_CACHE)?;

  if let Some(StoredProviderMetadata {
    metadata,
    jwks
  }) = kv_get(&kv, KEY_PROVIDER_METADATA).await? {
    return Ok(metadata.set_jwks(jwks))
  }

  // re-cache the provider metadata

  let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string())
    // valid static URL
    .unwrap();

  // Fetch Google's OpenID Connect discovery document.
  //
  // Note: We are using CoreProviderMetadata instead of GoogleProviderMetadata
  // because we don't care about token revocation.
  let provider_metadata = CoreProviderMetadata::discover_async(
    issuer_url,
    async_http_client
  ).await?;

  // cache it
  kv_put(
    &kv,
    KEY_PROVIDER_METADATA,
    &StoredProviderMetadataRef {
      jwks: provider_metadata.jwks(),
      metadata: &provider_metadata
    },
    Duration::hours(1)
  ).await?;
  
  Ok(provider_metadata)
}

/// Create a new OpenID Connect client from stored google secrets.
async fn new_client(env: &Env) -> Result<CoreClient, HandlerError> {
  // load secrets

  let google_client_id = ClientId::new(
    get_secret(env, Secret::GOOGLE_CLIENT_ID).to_string()
  );

  let google_client_secret = ClientSecret::new(
    get_secret(env, Secret::GOOGLE_CLIENT_SECRET).to_string()
  );

  let callback_uri = if env.var("ENVIRONMENT")
    .unwrap()
    .as_ref() == "dev"
  {
    "http://localhost:8787/callback".to_string()
  } else {
    format!(
      "{domain}/callback",
      domain = get_secret(env, Secret::WORKER_DOMAIN)
    )
  };

  let redirect_uri = RedirectUrl::new(callback_uri)?;

  let provider_metadata = get_provider_metadata(env).await?;

  // Set up the config for the Google OpenID Connect process.
  Ok(
    CoreClient::from_provider_metadata(
      provider_metadata,
      google_client_id,
      Some(google_client_secret),
    )
    // Google will redirect back to this Worker at the `/callback`
    // endpoint with `code` and `state` params like so:
    //   https://<subdomain>.<account_name>.workers.dev/callback?code=4%2F0AfJohXnTMTxxxxxxxx&state=abc123
    .set_redirect_uri(redirect_uri)
  )
}

pub struct GoogleAuthorize {
  pub redirect: Url,
  pub csrf: CsrfToken,
  pub nonce: Nonce
}
pub async fn get_google_auth_url(
  env: &Env,
  scopes: impl IntoIterator<Item = Scope>
) -> Result<GoogleAuthorize, HandlerError> {
  // Generate the authorization URL to which we'll redirect the user.
  let (redirect, csrf, nonce) = new_client(env).await?
    .authorize_url(
      AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
      // 23 bytes = 1/10^56 guess chance (UUID is 1/10^38).
      // These double as 10 minute passwords.
      || CsrfToken::new_random_len(23),
      Nonce::new_random,
    )
    .add_scope(Scope::new("email".to_string()))
    .add_scopes(scopes)
    .url();

  Ok(GoogleAuthorize { redirect, csrf, nonce })
}

pub struct GoogleIdToken {
  pub refresh_token: Option<RefreshToken>,
  pub user_email: EndUserEmail,
  pub subject: SubjectIdentifier,
  pub issue_time: DateTime<Utc>,
  pub expiration: DateTime<Utc>
}
/// Exchange the code for a token
pub async fn fetch_google_access_token(
  env: &Env,
  code: AuthorizationCode,
  google_nonce: &Nonce
) -> Result<GoogleIdToken, HandlerError> {
  let client = new_client(env).await?;
  
  let response = client.exchange_code(code)
    .request_async(async_http_client)
    .await;

  response_to_token(&client, response, google_nonce)
}

/// Exchange the code for a token
pub async fn fetch_google_refresh_token(
  env: &Env,
  token: &RefreshToken,
  google_nonce: &Nonce
) -> Result<GoogleIdToken, HandlerError> {
  let client = new_client(env).await?;
  
  let response = client.exchange_refresh_token(token)
    .request_async(async_http_client)
    .await;

  response_to_token(&client, response, google_nonce)
}

/// Return Google's ServerResponseError (if it did error), otherwise
/// grab the required values from the token
fn response_to_token(
  client: &CoreClient,
  response: Result<
    CoreTokenResponse,
    CoreRequestTokenError<AsyncHttpClientError>
  >,
  nonce: &Nonce,
) -> Result<GoogleIdToken, HandlerError> {
  // check for ServerResponse error
  let response = match response {
    Ok(ok) => ok,
    // Returning this error will forward it, including the
    // error code and message, to the client.
    Err(ServerResponse(e)) =>
      return Err(TokenErrorResponse::from(e).into()),
    Err(e) => return Err(e.into())
  };

  let Some(id_token) = response.extra_fields().id_token() else {
    return Err(HandlerError::MissingIdToken)
  };
    
  let claims = id_token.claims(
    &client.id_token_verifier(),
    nonce
  )?;

  let Some(user_email) = claims.email() else {
    return Err(HandlerError::MissingEmailClaim)
  };

  Ok(
    GoogleIdToken {
      refresh_token: response.refresh_token().cloned(),
      user_email: user_email.clone(),
      subject: claims.subject().clone(),
      issue_time: claims.issue_time(),
      expiration: claims.expiration(),
    }
  )
}