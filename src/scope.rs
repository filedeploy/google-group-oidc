use itertools::Itertools;
use openidconnect::core::CoreAuthErrorResponseType;

use crate::{endpoints::authorize_error::error, handler_error::HandlerError};

/// Adapted from https://github.com/HeroicKatora/oxide-auth/blob/019b7651e97a3ee2cde40b9806a1ecf37e051942/oxide-auth/src/primitives/scope.rs#L120
pub fn parse_scopes(scopes: &str) -> Result<impl Iterator<Item = &str>, HandlerError> {
  let mut invalid = scopes.chars()
    .filter(|chr| invalid_scope_char(*chr))
    .peekable();

  if invalid.peek().is_some() {
    return error(
      CoreAuthErrorResponseType::InvalidScope,
      format!(
        r#"Encountered invalid character(s) in scope: "{}""#,
        invalid.join(r#"", ""#)
      ).into()
    )
  }

  Ok(scopes.split(' ').filter(|s| !s.is_empty()))
}

fn invalid_scope_char(ch: char) -> bool {
  match ch {
      '\x21' => false,
      ch if ('\x23'..='\x5b').contains(&ch) => false,
      ch if ('\x5d'..='\x7e').contains(&ch) => false,
      ' ' => false, // Space separator is a valid char
      _ => true,
  }
}