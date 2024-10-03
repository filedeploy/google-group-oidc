use std::collections::BTreeMap;

use axum::{extract::State, response::{IntoResponse, Redirect, Response}, Form};
use chrono::Duration;
use openidconnect::{core::CoreAuthErrorResponseType, Scope};
use serde::Deserialize;
use url::Url;
use worker::{console_error, kv::KvStore, Env};

use crate::{consts::{get_secret, ClientSecret, Secret, KV_AUTHORIZE_STATE}, endpoints::authorize::authorize_error::{error, error_response, ErrorParams, ErrorResponse}, handler_error::HandlerError, google::{get_google_auth_url, GoogleAuthorize}, scope::parse_scopes, state::{kv_put, AuthorizeStateRef}};

/// legal values of the response_type field
#[derive(Deserialize)]
#[allow(non_camel_case_types)]
pub enum ResponseType {
  code
}
/// Sources:
///  https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.1
///  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
#[derive(Deserialize)]
pub struct AuthorizeParams {
  // this field is needed for validation / as an enum tag
  #[allow(dead_code)]
  response_type: ResponseType,
  client_id: String,
  redirect_uri: Url,
  state: String,
  nonce: String,
  scope: String
}

#[worker::send]
pub async fn authorize(
  State(env): State<Env>,
  Form(AuthorizeParams {
    response_type: _,
    client_id,
    redirect_uri,
    state,
    nonce,
    scope
  }): Form<AuthorizeParams>
) -> Response {
  match authorize_result(
    env,
    client_id,
    scope,
    &redirect_uri,
    nonce,
    &state
  ).await {
    Ok(ok) => ok,
    Err(e) => {
      // TODO: telemetry?
      console_error!("{e}");

      let response_params = match e {
        HandlerError::Authorize(params) => params,
        _ => ErrorParams {
          error: CoreAuthErrorResponseType::ServerError,
          error_description: None,
          error_uri: None
        }
      };

      error_response(
        redirect_uri,
        ErrorResponse {
          params: response_params,
          state: &state
        }
      )
    },
  }
}

async fn authorize_result<'a>(
  env: Env,
  client_id: String,
  scope: String,
  client_redirect: &Url,
  client_nonce: String,
  client_state: &str,
) -> Result<Response, HandlerError> {
  let groups_scope = &mut false;
  let openid_scope = &mut false;

  let scopes = parse_scopes(&scope)?.filter_map(
    |s| match s {
      "groups" => {
        // we accept "groups", but Google doesn't
        *groups_scope = true;
        None
      },
      "openid" => {
        *openid_scope = true;
        None
      },
      _ => Some(Scope::new(s.into()))
    }
  ).collect::<Vec<_>>();

  // Source: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequestValidation
  if !*openid_scope {
    return error(
      CoreAuthErrorResponseType::InvalidScope,
      r#"scope field must contain "openid""#.into()
    )
  }
  
  // TODO: implement the "token" and "id_token" flows
  //  https://www.rfc-editor.org/rfc/rfc6749.html#section-4.2.1
  //  https://openid.net/specs/openid-connect-core-1_0.html#Authentication

  // TODO: support loading client ids and redirects in a more generic way
  let client_secret = get_secret(&env, Secret::CLIENT_SECRETS);
  let client_map = serde_json::from_str::<
    BTreeMap<&str, ClientSecret>
  >(client_secret)?;
  let Some(client_secret) = client_map.get(client_id.as_str()) else {
    return error(
      CoreAuthErrorResponseType::AccessDenied,
      "Unregistered client_id".into()
    )
  };

  // Verify that this redirect uri is registered to this client
  if !client_secret.redirect_uris
    .iter()
    .any(|uri| uri == client_redirect)
  {
    return error(
      CoreAuthErrorResponseType::AccessDenied,
      "Unregistered redirect_uri".into()
    )
  }

  // Add the scopes from the client request
  // to the Google request, but no other params.
  let GoogleAuthorize {
    redirect: google_redirect,
    csrf: google_csrf,
    nonce: google_nonce
  } = get_google_auth_url(&env, scopes)
    .await?;

  // Key by csrf and serialize authorize_state
  kv_put(
    &KvStore::from_this(&env, KV_AUTHORIZE_STATE)?,
    google_csrf.secret(),
    &AuthorizeStateRef {
      client_id: &client_id,
      client_redirect,
      client_state,
      client_nonce: &client_nonce,
      google_nonce: &google_nonce,
      groups_scope: *groups_scope
    },
    Duration::minutes(10)
  ).await?;

  Ok(Redirect::to(google_redirect.as_str()).into_response())
}
