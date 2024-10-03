# These scripts pass secrets from Doppler to Wrangler.
# 
# You may use any secret other management tool, or just plain
# `wrangler secret`. This file is not required to run the worker and
# is purely for reference / my own convenience.

# Source: https://github.com/casey/just/pull/2180
set ignore-comments

[no-exit-message]
run-dev:
  @doppler secrets --project google-group-oidc --config dev_personal --json \
    | cargo run --bin process_secrets -- env > .dev.vars
  @npx --yes wrangler dev
  @rm .dev.vars

test CONFIG:
  @doppler run \
    --project google-group-oidc \
    --config {{CONFIG}} \
    --command='''kubectl oidc-login setup \
      --oidc-issuer-url=$WORKER_DOMAIN \
      --oidc-client-id=$CLIENT_ID'''

[no-exit-message]
test-dev:
  @just test dev_personal

[no-exit-message]
test-prod:
  @just test prd

[no-exit-message]
deploy-prod:
  @doppler secrets --project google-group-oidc --config prd --json \
    | cargo run --bin process_secrets -- json \
      | npx wrangler secret bulk --env prod
  @npx wrangler deploy --env prod