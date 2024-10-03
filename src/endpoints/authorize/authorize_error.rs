use core::fmt;
use std::{borrow::Cow, fmt::{Display, Formatter}};

use axum::{http::{header, StatusCode}, response::{IntoResponse, Response}};
use openidconnect::core::CoreAuthErrorResponseType;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::handler_error::HandlerError;

/// Sources:
///   https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
///   https://openid.net/specs/openid-connect-core-1_0.html#AuthError
#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse<'a> {
  #[serde(flatten)]
  pub params: ErrorParams,
  pub state: &'a str,
}
#[derive(Serialize, Deserialize, thiserror::Error, Debug)]
pub struct ErrorParams {
  // Use static Cow rather than enum so we can deserialize
  // non-standard values
  pub error: CoreAuthErrorResponseType,
  pub error_description: Option<Cow<'static, str>>,
  pub error_uri: Option<String>
}
impl Display for ErrorParams {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "error: {e}{opt}",
      e = self.error.as_ref(),
      opt = if let Some(desc) = &self.error_description {
        format!(", error_description: {desc}")
      } else {
        "".into()
      }
    )
  }
}

pub fn error<T>(
  error: CoreAuthErrorResponseType,
  description: Cow<'static, str>
) -> Result<T, HandlerError> {
  Err(
    HandlerError::Authorize(
      ErrorParams {
        error,
        error_description: Some(description),
        error_uri: None
      }
    )
  )
}

pub fn error_response(
  mut client_redirect: Url,
  response: ErrorResponse,
) -> Response {
  client_redirect.set_query(
    Some(
      &serde_urlencoded::to_string(response)
        // ErrorResponse's Deserialize impl doesn't return errors
        .unwrap()
    )
  );

  (
    StatusCode::FOUND,
    [(header::LOCATION, client_redirect.as_str())]
  ).into_response()
}