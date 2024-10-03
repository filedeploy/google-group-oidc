# Google Group OIDC

An OpenID Connect (OIDC) server that wraps Google's OIDC server and adds [support for groups claims](https://stackoverflow.com/a/35423190) to validate users's workplace permissions (RBAC).

This project has been tested with [Kubelogin](https://github.com/int128/kubelogin) but can be used with any OIDC client.

It uses a Cloudflare Worker rather than container services like fly.io or Fargate to minimize cost of periodic/sparse requests and latency.

Alternatively, using [Okta as your idP](https://help.okta.com/en-us/content/topics/provisioning/google/google-provisioning.htm) at $1,500+/year solves this issue.

## Setup

### Option A: Nix

1. Install [Nix](https://nixos.org/download/)
2. `cd` into the repo dir
3. `nix develop ./dev-setup`
4. Proceed to [Deployment](#deployment)

### Option B: Manual

1. Install [Rustup](https://www.rust-lang.org/tools/install) and follow the "_Configuring the PATH environment variable_" guide
2. Install [Node.js](https://nodejs.org/en/download/prebuilt-installer/current)
3. Run `cargo install wasm-pack worker-build`
4. Proceed to [Deployment](#deployment)

### Deployment

1. Run `npx wrangler login` and login to Cloudflare
2. Run `npx wrangler kv namespace create <NAMESPACE>` for each namespace listed in `wrangler.toml` (KV_AUTHORIZE_STATE, KV_ACCESS_TOKEN_STATE, KV_REFRESH_TOKEN_STATE, ...) and replace those `wrangler.toml` values.
3. Upload your [Secrets](#secrets)
4. Use `npx wrangler deploy --env prod` to publish to production

### Development

- Use `npx wrangler dev` to test locally

## Secrets

The Worker requires the following secrets. You can upload them via [Wrangler](https://developers.cloudflare.com/workers/configuration/secrets/#via-wrangler), [Cloudflare Dashboard](https://developers.cloudflare.com/workers/configuration/secrets/#via-the-dashboard), or test locally with a [`.dev.vars` file](https://developers.cloudflare.com/workers/configuration/secrets/#local-development-with-secrets):

### Secrets

Randomly generated 32 character string. Used for testing but not production:

```bash
CLIENT_ID='aeiou...'
```

Json map of registered clients and their allowed redirect uris. The key (e.g. "aeiou") should match $CLIENT_ID. Keep in mind `localhost` doesn't support `https`:

```bash
CLIENT_SECRETS='{"aeiou":{"redirect_uris":["http://localhost:8000", "http://localhost:1800"]}}'
```

The OAuth 2.0 Client IDs generated from [here](https://console.cloud.google.com/apis/credentials):

```bash
GOOGLE_CLIENT_ID='1234567890-4y5cqwxpq34ypco4y5x.apps.googleusercontent.com'
```

The OAuth 2.0 Client secret generated from [here](https://console.cloud.google.com/apis/credentials):

```bash
GOOGLE_CLIENT_SECRET='GOCSPX-cwnyo38y74x5oqy45pmq8y'
```

Email account of the admin user the Service Account will impersonate:

```bash
GOOGLE_ADMIN_EMAIL='admin.user@workplacedomain.com'
```

The JSON contents of the file generated when a new Service Account is created [here](https://console.cloud.google.com/apis/credentials):

```bash
GOOGLE_SERVICEACCOUNT_KEY='{
  "type": "service_account",
  "project_id": "...",
  "private_key_id": "...",
  "private_key": "...",
  "client_email": "serviceaccountname@projectname.iam.gserviceaccount.com",
  "client_id": "...",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/serviceaccountnbame%40projectname.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}'
```

Workspace domain to filter group members by:

```bash
GOOGLE_WORKSPACE_DOMAIN='workspacedomain.com'
```

Randomly generated public and private JSON Web Keys. [Example](https://mkjwk.org/) (Set **Show X.509** to **Yes**):

```bash
JWK_PRIVATE='-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----'
JWK_PUBLIC='{
  "kty":"RSA",
  "e":"AQAB",
  "use":"sig",
  "kid":"...",
  "alg":"RS256",
  "n":"..."
}'
```

Domain your worker is hosted at:

```bash
WORKER_DOMAIN='https://workername.accountname.workers.dev'
```

## TODO

- Add docs that explain what each secret is and how to get them in better detail.
- Get it working without Domain Wide Delegation?
  - [Blog Post](https://workspaceupdates.googleblog.com/2020/08/use-service-accounts-google-groups-without-domain-wide-delegation.html)
  - [Outdated Java docs](https://cloud.google.com/identity/docs/how-to/setup#auth-no-dwd)
- One-command deploy
  - Autogenerate secrets instead of making implementors do it.
  - Wrap install, wrangler login, kv namespace create, secret upload, and deploy into a single action.
- OpenTelemetry Traces/metrics/logs?
