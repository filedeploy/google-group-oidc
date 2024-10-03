use std::ops::{Deref, DerefMut};

use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use openidconnect::{core::CoreErrorResponseType, StandardErrorResponse};

use crate::{consts::TOKEN_HEADER, handler_error::HandlerError};

type InnerErr = StandardErrorResponse<CoreErrorResponseType>;

#[derive(thiserror::Error, Debug)]
#[error("{}", .0)]
pub struct TokenErrorResponse(InnerErr);
impl From<InnerErr> for TokenErrorResponse {
  fn from(value: InnerErr) -> Self {
    TokenErrorResponse(value)
  }
}
impl Deref for TokenErrorResponse {
  type Target = InnerErr;

  fn deref(&self) -> &Self::Target {
      &self.0
  }
}
impl DerefMut for TokenErrorResponse {
  fn deref_mut(&mut self) -> &mut Self::Target {
      &mut self.0
  }
}

pub fn error<T>(
  error: CoreErrorResponseType,
  description: Option<String>
) -> Result<T, HandlerError> {
  Err(
    TokenErrorResponse(
      StandardErrorResponse::new(error, description, None)
    ).into()
  )
}

pub fn error_response(response: TokenErrorResponse) -> Response {
  (
    StatusCode::BAD_REQUEST,
    TOKEN_HEADER,
    Json(response.0)
  ).into_response()
}