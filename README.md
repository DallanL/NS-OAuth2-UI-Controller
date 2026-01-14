# NetSapiens Custom OAuth2 UI Controller

## Overview
This repository contains a custom CakePHP controller (`AuthorizeController.php`) designed for self-hosted NetSapiens platforms.

The standard NetSapiens `Oauth2Controller` is a headless API intended for programmatic access or "Magic Link" email flows. It does not provide a visual login interface for users to enter credentials.

This custom controller bridges that gap by providing:
1.  **A visual HTML Login Form** (rendered directly, no View files required).
2.  **Standard OAuth2 "Authorization Code" Flow** support.
3.  **Server-side Client Configuration** for "clean" URLs (hiding Client IDs).
4.  **Workaround for Upstream API Quirks** (specifically the `username` requirement during token exchange).

## Installation

### 1. Deploy the File
Place the `AuthorizeController.php` file into the NetSapiens API Controller directory.

```bash
cp AuthorizeController.php /var/www/html/ns-api/Controller/AuthorizeController.php
```

### 2. Set Permissions
Ensure the file is owned by the web server user (usually www-data or apache) and matches the permissions of existing controllers.

```bash
chown www-data:www-data /var/www/html/ns-api/Controller/AuthorizeController.php
chmod 644 /var/www/html/ns-api/Controller/AuthorizeController.php
```

## Usage Guide

### Step 1: Initiating Login (The Browser)
Direct your user's browser to the controller.

```
https://{api-domain}/ns-api/authorize/index?client_id={ID}&redirect_uri={URL}&response_type=code&state={RANDOM_STRING}
```

### Step 2: The Callback
After successful authentication, the user is redirected to your redirect_uri with three parameters:
```
https://{redirect-uri}?code=AUTH_CODE_HERE&state=YOUR_STATE&username=AUTH_USERNAME
```

### Step 3: Token Exchange (The Server)
IMPORTANT: The NetSapiens core Oauth2Controller has a non-standard requirement. You must pass the username parameter in your POST request to exchange the code for a token. Standard OAuth2 libraries will fail unless you inject this parameter.

cURL Example:
```bash
curl -X POST https://{api-domain}/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "client_id={YOUR_CLIENT_ID}" \
     -d "client_secret={YOUR_CLIENT_SECRET}" \
     -d "redirect_uri={YOUR_CALLBACK_URL}" \
     -d "code={CODE_FROM_STEP_2}" \
     -d "username={USERNAME_FROM_STEP_2}"
```

## Security Considerations
1. HTTPS Is Mandatory: This controller handles cleartext passwords in the form submission. It must never be exposed over HTTP.
2. CSRF Protection: Always generate a random state string in your client application before redirecting the user. Verify that the state returned in the callback matches what you stored.
3. Database Validation: The script includes logic to cross-reference the redirect_uri against the Oauthclient database table. Ensure your Client IDs are correctly set up in the NetSapiens database with the exact Redirect URIs you intend to use.
