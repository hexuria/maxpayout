# OAuth 2.0 Social Sign-In Configuration Manual

This document provides a step-by-step setup guide for configuring secure OAuth 2.0 social authentication (Google, Apple, Microsoft, Facebook) for the MaxPayout web application. 

Because the backend operates within a sandboxed WebAssembly (WASI) runtime under Fermyon Spin, outgoing backchannel requests are strictly restricted by default. This manual covers both developer portal registration and WASI networking configurations.

---

## 1. Global Setup Context

All providers require a base redirect URL. The system dynamically constructs redirect URIs using the `OAUTH_REDIRECT_BASE_URL` environment variable.

| Variable Name | Typical Local Value | Typical Production Value | Description |
| :--- | :--- | :--- | :--- |
| `OAUTH_REDIRECT_BASE_URL` | `http://localhost:3000` | `https://maxpayout.com` | Base scheme + host + port where the app is being run. |

> [!IMPORTANT]
> Do not append a trailing slash `/` to the `OAUTH_REDIRECT_BASE_URL` value. The codebase automatically appends the callback paths (`/api/auth/callback/<provider>`).

---

## 2. Step-by-Step Provider Setup Guides

### 🟢 Google OAuth 2.0
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com).
2. Create or select a Google Cloud project.
3. Configure your **OAuth Consent Screen**:
   - Choose **External** user type.
   - Enter your app name, developer support email, and contact details.
   - Add scopes: `openid`, `.../auth/userinfo.email`, and `.../auth/userinfo.profile`.
4. Go to **Credentials** -> **Create Credentials** -> **OAuth Client ID**:
   - Choose **Web application** as application type.
   - Name your client (e.g., `MaxPayout Development`).
   - Add **Authorized Redirect URIs**:
     - Local: `http://localhost:3000/api/auth/callback/google`
     - Production: `https://yourdomain.com/api/auth/callback/google`
5. Copy your **Client ID** and **Client Secret** and insert them into your `.env` file.

```bash
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-google-client-secret
```

---

###  Sign in with Apple (SIWA)
Sign in with Apple requires dynamic client secret JWT token generation using an Elliptic Curve (EC) private key with ES256 signing.

1. Navigate to the [Apple Developer Portal](https://developer.apple.com).
2. Under **Identifiers**:
   - Click `+` and choose **App IDs**. Register an App ID (e.g., `com.goldcoders.maxpayout`). Enable **Sign In with Apple**.
   - Click `+` again and choose **Services IDs**. Register a Services ID (e.g., `com.goldcoders.maxpayout.service`).
     - This Services ID value is your `APPLE_CLIENT_ID`.
     - Enable and configure **Sign In with Apple** on the Services ID.
     - Associate it with your primary App ID.
     - Enter your domain and the exact Return URL: `https://yourdomain.com/api/auth/callback/apple`.
3. Under **Keys**:
   - Register a new key (e.g., `MaxPayout SIWA Key`).
   - Enable **Sign In with Apple**, click configure, and select your primary App ID.
   - Save and download the private key file (e.g., `AuthKey_KEY1234567.p8`). This contains your PEM private key.
4. Retrieve your **Team ID** (visible in top-right of portal).
5. Extract key credentials and insert them into your `.env` file:

```bash
APPLE_CLIENT_ID=com.goldcoders.maxpayout.service
APPLE_TEAM_ID=ABC123XYZ
APPLE_KEY_ID=KEY1234567
# Note the escaped \n characters for multiline PEM storage in environment variables
APPLE_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg...\n-----END PRIVATE KEY-----"
```

> [!WARNING]
> Apple strictly rejects non-HTTPS redirect URLs for Services IDs in production. For local testing, you must use a tunneling tool (such as ngrok or Cloudflare Tunnels) or utilize the Google/Microsoft mock flows.

---

### 🔵 Microsoft Entra ID (Azure AD)
1. Navigate to the [Microsoft Entra Admin Center](https://entra.microsoft.com) or [Azure Portal](https://portal.azure.com).
2. Go to **Identity** -> **Applications** -> **App registrations** -> **New registration**.
3. Configure application parameters:
   - Name your application (e.g., `MaxPayout`).
   - Choose Supported Account Types (e.g., **Accounts in any organizational directory (Multitenant) and personal Microsoft accounts** for broadest reach).
   - Set Redirect URI: Platform **Web**, Value: `http://localhost:3000/api/auth/callback/microsoft`.
4. Register the app, then copy the **Application (client) ID** from the overview page.
5. Go to **Certificates & secrets** -> **Client secrets** -> **New client secret**:
   - Provide a description and expiration.
   - Click **Add**.
   - Copy the **Secret Value** (not Secret ID) immediately.
6. Verify API Permissions: Default should grant delegated `User.Read` on Microsoft Graph. Add permissions if missing.
7. Map these parameters inside your `.env` file:

```bash
MICROSOFT_CLIENT_ID=your-microsoft-client-guid
MICROSOFT_CLIENT_SECRET=your-microsoft-secret-value
```

---

### 🔵 Facebook Login (Meta)
1. Navigate to the [Meta for Developers Portal](https://developers.facebook.com).
2. Go to **My Apps** -> **Create App**.
3. Choose your app type (e.g., select **Authenticate and request data from users with Facebook Login**).
4. Provide your App Name and contact email.
5. In your App Dashboard, find **Facebook Login** under products and click **Set Up**:
   - Select **Web (WWW)**.
   - Go to **Facebook Login** -> **Settings** in the left sidebar.
   - Enter **Valid OAuth Redirect URIs**:
     - Local: `http://localhost:3000/api/auth/callback/facebook`
     - Production: `https://yourdomain.com/api/auth/callback/facebook`
6. Go to **App Settings** -> **Basic** in the left sidebar.
7. Copy your **App ID** and **App Secret** into your `.env` file.

```bash
FACEBOOK_CLIENT_ID=your-facebook-app-id
FACEBOOK_CLIENT_SECRET=your-facebook-app-secret
```

---

## 3. Sandboxed WASI Network Configuration

Because this application runs inside Fermyon Spin's sandboxed environment, outgoing HTTP requests to OAuth endpoints will fail unless they are explicitly authorized.

These allowed hosts are configured in the `web/spin.toml` manifest file under `allowed_outbound_hosts`.

```toml
[component.web]
allowed_outbound_hosts = [
  "https://api.resend.com",
  "https://api.resend.com:443",
  "https://oauth2.googleapis.com",
  "https://openidconnect.googleapis.com",
  "https://www.googleapis.com",
  "https://appleid.apple.com",
  "https://login.microsoftonline.com",
  "https://graph.microsoft.com",
  "https://graph.facebook.com",
  "https://www.facebook.com",
  "http://127.0.0.1:9001",
  "http://localhost:9001"
]
```

> [!NOTE]
> If you integrate other OAuth providers or use non-standard tenants (e.g. single-tenant Azure endpoints), you must add their respective API hostnames to the `allowed_outbound_hosts` array in `web/spin.toml`.

---

## 4. Testing Locally

To run the application locally with full environment variables loaded:

1. Copy [.env.example](../.env.example) to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Open your `.env` file and replace the placeholder values with your newly acquired credentials.
3. Start the application under Spin:
   ```bash
   make spin
   ```
4. Access `http://localhost:3000` (or the port defined in your makefile) to test the flows.

## 5. Testing Without Real Provider Credentials

For local automated or manual fake-provider testing, run the local provider in one terminal:

```bash
make fake-oauth
```

Then keep the normal `*_CLIENT_ID` and `*_CLIENT_SECRET` values set to fake test values, and override the provider endpoints:

```bash
GOOGLE_CLIENT_ID=google-client
GOOGLE_CLIENT_SECRET=google-secret
OAUTH_GOOGLE_AUTH_URL=http://127.0.0.1:9001/google/authorize
OAUTH_GOOGLE_TOKEN_URL=http://127.0.0.1:9001/google/token
OAUTH_GOOGLE_JWKS_URL=http://127.0.0.1:9001/google/jwks
OAUTH_GOOGLE_ISSUER=http://127.0.0.1:9001/google

APPLE_CLIENT_ID=apple-client
OAUTH_APPLE_AUTH_URL=http://127.0.0.1:9001/apple/authorize
OAUTH_APPLE_TOKEN_URL=http://127.0.0.1:9001/apple/token
OAUTH_APPLE_JWKS_URL=http://127.0.0.1:9001/apple/jwks
OAUTH_APPLE_ISSUER=http://127.0.0.1:9001/apple

MICROSOFT_CLIENT_ID=microsoft-client
MICROSOFT_CLIENT_SECRET=microsoft-secret
OAUTH_MICROSOFT_AUTH_URL=http://127.0.0.1:9001/microsoft/authorize
OAUTH_MICROSOFT_TOKEN_URL=http://127.0.0.1:9001/microsoft/token
OAUTH_MICROSOFT_JWKS_URL=http://127.0.0.1:9001/microsoft/jwks
OAUTH_MICROSOFT_ISSUER=http://127.0.0.1:9001/microsoft/{tenantid}/v2.0

FACEBOOK_CLIENT_ID=facebook-client
FACEBOOK_CLIENT_SECRET=facebook-secret
OAUTH_FACEBOOK_AUTH_URL=http://127.0.0.1:9001/facebook/authorize
OAUTH_FACEBOOK_TOKEN_URL=http://127.0.0.1:9001/facebook/token
OAUTH_FACEBOOK_PROFILE_URL=http://127.0.0.1:9001/facebook/me?fields=id,email,name
```

The app uses the same redirect, code exchange, PKCE, JWKS selection, ID-token verification, and Facebook profile mapping paths against these fake endpoints, so tests can run without Google, Apple, Microsoft, or Facebook developer credentials.
