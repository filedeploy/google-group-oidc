use axum::{extract::State, http::StatusCode, response::{IntoResponse, Response}, Form, Json};
use openidconnect::{core::CoreErrorResponseType, AuthorizationCode};
use serde::{Deserialize, Serialize};
use url::Url;
use worker::{console_error, kv::KvStore, Env};

use crate::{consts::{KV_ACCESS_TOKEN_STATE, KV_REFRESH_TOKEN_STATE, TOKEN_HEADER}, endpoints::token_error::{error, error_response}, google::{fetch_google_access_token, fetch_google_refresh_token, GoogleIdToken}, groups::get_user_groups, handler_error::HandlerError, oidc_token::{create_oidc_token, new_token}, state::{kv_get, store_refresh_token_state, AccessTokenState, CommonTokenState, RefreshTokenState}};

// Sources:
//  https://serde.rs/enum-representations.html#internally-tagged
//  https://stackoverflow.com/a/70380491
//
// `#[serde(tag = "grant_type")]` matches against the value of the
// `grant_type` field:
// 
// switch params.grant_type {
//   "authorization_code" => CodeParams { ... },
//   "refresh_token" => RefreshToken { ... },
//   other => panic!()
// }
//
/// Supports params in either authorization_code for refresh_token
/// format.
#[derive(Deserialize)]
#[serde(tag = "grant_type")]
pub enum Params {
  #[serde(rename = "authorization_code")]
  Code(CodeParams),
  /// Source: https://www.rfc-editor.org/rfc/rfc6749#section-6
  #[serde(rename = "refresh_token")]
  Refresh{ refresh_token: String }
}
/// Source: https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
#[derive(Deserialize)]
pub struct CodeParams {
  code: AuthorizationCode,
  redirect_uri: Url,
  client_id: String
}

/// Sources:
///   https://www.rfc-editor.org/rfc/rfc6749#section-5.1
///   https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
#[derive(Serialize)]
pub struct TokenResponse {
  access_token: String,
  token_type: &'static str,
  expires_in: u32,
  refresh_token: Option<String>,
  id_token: String
}

/// Axum handler function for the `/token` endpoint
#[worker::send]
pub async fn token(
  State(env): State<Env>,
  Form(params): Form<Params>
) -> Response {  
  let result = match params {
    Params::Code(c) => access_token(c, env).await,
    Params::Refresh{ refresh_token: r } => refresh_token(r, env).await
  };

  match result {
    Ok(ok) => ok,
    Err(e) => {
      // TODO: telemetry?
      console_error!("{e}");

      let response_params = match e {
        HandlerError::Token(p) => p,
        _ => return (
          StatusCode::INTERNAL_SERVER_ERROR,
          TOKEN_HEADER
        ).into_response(),
      };

      error_response(response_params)
    }
  }
}

async fn access_token(
  CodeParams { code, redirect_uri, client_id }: CodeParams,
  env: Env
) -> Result<Response, HandlerError> {
  // fetch access token state
  let Some(AccessTokenState {
    common: CommonTokenState {
      client_id: stored_client_id,
      client_nonce,
      google_nonce,
      groups_scope
    },
    client_redirect,
    google_code
  }) = kv_get(
    &KvStore::from_this(&env, KV_ACCESS_TOKEN_STATE)?,
    code.secret()
  ).await?
    else {
      // No stored access token = user isn't authorized
      return error(
        CoreErrorResponseType::InvalidGrant,
        Some("Invalid code".into())
      )
    };

  // ensure matching client_id
  if client_id != stored_client_id {
    return error(
      CoreErrorResponseType::InvalidGrant,
      Some("Invalid code".into())
    )
  }
  // ensure matching redirect_url
  if redirect_uri != client_redirect {
    return error(
      CoreErrorResponseType::InvalidGrant,
      Some("redirect_url does not match registered".into())
    )
  }

  // get access and refresh tokens
  let GoogleIdToken {
    refresh_token: google_refresh,
    user_email,
    subject: google_subject,
    issue_time,
    expiration
  } = fetch_google_access_token(
    &env,
    google_code,
    &google_nonce
  ).await?;

  // query google group endpoint for our user's group membership
  let groups = if groups_scope {
    Some(get_user_groups(&env, &user_email).await?)
  } else {
    None
  };

  // generate client tokens
  let access_token = create_oidc_token(
    &env,
    &client_id,
    &client_nonce,
    google_subject,
    issue_time,
    expiration,
    groups
  )?;

  // If google gave us a refresh token (it should),
  // cache our own refresh token along with google's
  // access+refresh token for one year.
  let refresh_token = match google_refresh {
    None => None,
    Some(google_refresh) => {
      let client_refresh = new_token::<32>();

      store_refresh_token_state(
        &env,
        &client_refresh,
        &RefreshTokenState {
          common: CommonTokenState {
            client_id,
            client_nonce,
            google_nonce,
            groups_scope,
          },
          google_refresh
        }
      ).await?;

      Some(client_refresh)
    }
  };

  Ok(token_response(access_token, refresh_token))
}

async fn refresh_token(
  refresh_token: String,
  env: Env
) -> Result<Response, HandlerError> {
  let kv = KvStore::from_this(&env, KV_REFRESH_TOKEN_STATE)?;

  // fetch refresh token state
  let Some(mut refresh_token_state) = kv_get(&kv, &refresh_token)
    .await?
    else {
      // No stored refresh token = user isn't authorized
      return error(
        CoreErrorResponseType::InvalidGrant,
        Some("Invalid refresh_token".into())
      )
    };

  let RefreshTokenState {
    common: CommonTokenState {
      client_id,
      client_nonce,
      google_nonce,
      groups_scope
    },
    google_refresh
  } = &refresh_token_state;

  // get access and refresh tokens
  let GoogleIdToken {
    refresh_token: new_google_refresh,
    user_email,
    subject: google_subject,
    issue_time,
    expiration
  } = match fetch_google_refresh_token(
    &env,
    google_refresh,
    google_nonce
  ).await {
    Ok(ok) => ok,
    Err(e) => {
      match e {
        // If the Google refresh token is revoked or expired
        HandlerError::Token(ref t)
          if *t.error() == CoreErrorResponseType::InvalidGrant =>
        {
          // revoke the client's refresh token too
          kv.delete(&refresh_token).await?;
        },
        _ => ()
      }

      return Err(e)
    }
  };

  let groups = if *groups_scope {
    Some(get_user_groups(&env, &user_email).await?)
  } else {
    None
  };

  let id_token = create_oidc_token(
    &env,
    client_id,
    client_nonce,
    google_subject,
    issue_time,
    expiration,
    groups
  )?;

  match new_google_refresh {
    // This case probably won't occur
    Some(new_google_refresh)
      if new_google_refresh.secret() != google_refresh.secret() =>
    {
      // update refresh token state and store it
      refresh_token_state.google_refresh = new_google_refresh;
      store_refresh_token_state(
        &env,
        &refresh_token,
        &refresh_token_state
      ).await?;

      // We don't need to generate a new refresh token for the client
      // here. Our existing token's ttl was extended by the
      // `store_refresh_token_state` function.
    },
    _ => (),
  }

  Ok(token_response(id_token, Some(refresh_token)))
}

fn token_response(id_token: String, refresh_token: Option<String>) -> Response {
  (
    TOKEN_HEADER,
    // Source: https://openid.net/specs/openid-connect-core-1_0.html#TokenResponse
    Json(TokenResponse {
      access_token: new_token::<16>(),
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token,
      id_token
    })
  ).into_response()
}