# Fake OAuth Provider

Local OAuth/OIDC provider for MaxPayout browser smoke tests. It requires no real Google, Apple, Microsoft, or Facebook credentials.

## Run

```bash
make fake-oauth
```

or:

```bash
cd tools/fake-oauth-provider
cargo run -- --host 127.0.0.1 --port 9001
```

## Endpoints

Each provider supports:

```text
/{provider}/authorize
/{provider}/token
/{provider}/jwks
/{provider}/me
```

Valid providers are `google`, `apple`, `microsoft`, and `facebook`.

The server stores authorization codes in memory, validates one-time code use, validates PKCE `S256`, signs OIDC ID tokens with generated RS256 keys, serves JWKS, and returns a Facebook Graph-style `/me` response.
