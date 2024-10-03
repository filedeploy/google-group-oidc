use std::{collections::BTreeMap, io::{self, stdout}};

use clap::{Parser, ValueEnum};
use serde::Deserialize;

#[derive(Deserialize)]
struct Secret {
  computed: String
}

type Secrets = BTreeMap<String, Secret>;

#[derive(Parser)]
struct Args {
  #[arg(value_enum)]
  output: Output
}

#[derive(ValueEnum, Clone)]
enum Output {
  /// Output the result in json format
  Json,
  /// Output the result in .env format
  Env,
}

/// Takes Doppler json secrets from stdin and outputs either
/// `wrangler secrets` or .env compatible values
fn main() {
  let Args{ output } = Args::parse();

  let secrets = serde_json::from_reader::<_, Secrets>(
    io::stdin().lock()
  ).unwrap()
    .into_iter()
    .map(|(k, v)| {
      let v = v.computed;

      // guard against stupid Doppler feature
      assert_ne!(v, "<no value>");

      (k, v)
    });

  match output {
    // json
    Output::Json => serde_json::to_writer(
      stdout(),
      &secrets.collect::<BTreeMap<String, String>>()
    ).unwrap(),
    // env
    Output::Env => print!(
      "{}",
      secrets.map(|(k, v)| format!("{k}='{v}'"))
        .collect::<Vec<_>>()
        .join("\n")
    )   
  }
}