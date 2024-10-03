use axum::{extract::{Query, State}, http::{header, StatusCode}, response::{IntoResponse, Response}};
use chrono::Duration;
use openidconnect::{core::CoreAuthErrorResponseType, AuthorizationCode, Nonce};
use serde::Deserialize;
use url::Url;
use worker::{console_error, kv::KvStore, Env};

use crate::{consts::{KV_ACCESS_TOKEN_STATE, KV_AUTHORIZE_STATE}, endpoints::authorize_error::{error_response, ErrorResponse}, handler_error::HandlerError, oidc_token::new_token, state::{kv_get, kv_put, AccessTokenStateRef, AuthorizeState, CommonTokenStateRef}};

use super::authorize_error::ErrorParams;

// Source: https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2
#[derive(Deserialize)]
#[serde(untagged)]
pub enum CallbackEnum {
  Callback{
    code: AuthorizationCode
  },
  Error(ErrorParams)
}
#[derive(Deserialize)]
pub struct CallbackParams {
  #[serde(flatten)]
  params: CallbackEnum,
  state: String,
}

#[worker::send]
pub async fn callback(
  State(env): State<Env>,
  Query(CallbackParams {
    params,
    // We send `state` to Google in the /authorize request. It expires
    // after 10 minutes, and Google must redirect back to this endpoint
    // with `state` untouched, so it's effectively a one-time password.
    state: google_state
  }): Query<CallbackParams>
) -> Response {
  let AuthorizeState {
    client_id,
    client_redirect,
    client_state,
    client_nonce,
    google_nonce,
    groups_scope
  } = match fetch_authorize_state(
      &env,
      &google_state
    ).await {
      Ok(ok) => ok,
      Err(e) => {
        // TODO: telemetry?
        console_error!("{e}");

        // We couldn't retrieve the client_redirect url. Return a 401.
        return StatusCode::UNAUTHORIZED.into_response()
      }
    };
  
  let google_code = match params {
    CallbackEnum::Callback { code } => code,
    CallbackEnum::Error(params) => {
      // TODO: telemetry?
      console_error!(
        "Google authorize: {r}",
        r = serde_json::to_string(&params)
          // ErrorParams' Deserialize impl doesn't return errors
          .unwrap()
      );

      return error_response(
        client_redirect,
        ErrorResponse {
          params,
          state: &client_state
        }
      )
    },
  };

  match callback_result(
    &env,
    &google_code,
    &client_id,
    client_redirect.clone(),
    &client_state,
    &client_nonce,
    &google_nonce,
    groups_scope
  ).await {
    Ok(ok) => ok,
    Err(e) => {
      // TODO: telemetry?
      console_error!("{e}");

      error_response(
        client_redirect,
        ErrorResponse {
          params: ErrorParams {
            error: CoreAuthErrorResponseType::ServerError,
            error_description: None,
            error_uri: None
          },
          state: &client_state
        }
      )
    },
  }
}

async fn fetch_authorize_state(
  env: &Env,
  google_state: &str
) -> Result<AuthorizeState, HandlerError> {
  let kv_name = KV_AUTHORIZE_STATE;

  let kv = KvStore::from_this(env, kv_name)?;

  // use google_state as the key for the authorization state
  let Some(authorize_state) = kv_get(&kv, google_state)
    .await?
    else {
      return Err(HandlerError::KvMissing {
        kv_name,
        key: google_state.to_string()
      })
    };

  Ok(authorize_state)
}

async fn callback_result(
  env: &Env,
  google_code: &AuthorizationCode,
  client_id: &str,
  mut client_redirect: Url,
  client_state: &str,
  client_nonce: &str,
  google_nonce: &Nonce,
  groups_scope: bool
) -> Result<Response, HandlerError> {
  // Generate our own code
  let client_code = new_token::<16>();

  // Store the client id, redirect, csrf, google_code,
  // and google_nonce using client_code as the key.
  kv_put(
    &KvStore::from_this(env, KV_ACCESS_TOKEN_STATE)?,
    &client_code,
    &AccessTokenStateRef {
      common: CommonTokenStateRef {
        client_id,
        client_nonce,
        google_nonce,
        groups_scope
      },
      client_redirect: &client_redirect,
      google_code
    },
    Duration::minutes(10)
  ).await?;

  // Section 4.1 step C (https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1)
  // 
  // Google redirected the browser to this endpoint `/callback`.
  // Redirect the browser again back to the client's redirect_uri.
  let mut query = client_redirect.query_pairs_mut();
  query.append_pair("code", &client_code);
  query.append_pair("state", client_state);
  drop(query);

  Ok((
    StatusCode::FOUND,
    [(header::LOCATION, client_redirect.as_str())]
  ).into_response())
}