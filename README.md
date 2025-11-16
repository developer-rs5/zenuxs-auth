# 🔐 Zenuxs OAuth – Lightweight OAuth 2.0 + PKCE Client

A lightweight JavaScript OAuth 2.0 + PKCE client for integrating **Zenuxs Accounts** into browser apps, SPAs, and front-end applications.

This library provides:
- OAuth 2.0 Authorization Code + PKCE flow  
- Popup login support  
- Automatic token refresh  
- Token storage handling  
- Built-in event listeners  
- Clean authentication API  

Only the **package features** are documented below.

---

# 🚀 Load the Library

```html
<script src="https://cdn.jsdelivr.net/npm/zenuxs-oauth/dist/zenux-oauth.min.js"></script>
```

---

# 🧩 Creating a ZenuxOAuth Instance

```js
const oauth = new ZenuxOAuth({
    clientId: "YOUR_CLIENT_ID",
    redirectUri: "https://your-app.com/callback.html",
    scopes: "openid profile email",
    storage: "sessionStorage",
    autoRefresh: true,
    debug: true
});
```

### 🔍 What the package handles:
- Builds PKCE challenge + verifier  
- Manages OAuth URLs  
- Token storage (access + refresh token)  
- Automatic token refresh if enabled  
- Logs internal events when `debug: true`  

---

# 🔐 1. Login (Redirect Flow)

```js
oauth.login();
```

### Package does:
- Generates PKCE  
- Redirects user to Zenuxs login  
- Stores temporary OAuth state  

---

# 🪟 2. Login (Popup Flow)

```js
const tokens = await oauth.login({ popup: true });
```

### Package does:
- Opens login page in a popup  
- Waits for authorization code  
- Exchanges code → tokens  
- Returns tokens immediately  
- No full-page reload  

---

# 🔄 3. Handling OAuth Callback

```js
const tokens = await oauth.handleCallback();
```

### Package does:
- Reads `?code=` from redirect  
- Exchanges code for access + refresh tokens  
- Validates state  
- Saves tokens securely  
- Clears login code from URL  

---

# 👤 4. Get User Info

```js
const user = await oauth.getUserInfo();
```

### Package does:
- Calls `/userinfo` endpoint  
- Automatically attaches access token  
- Returns all claims from the server  

---

# 🔓 5. Check Authentication

```js
oauth.isAuthenticated();
```

### Package does:
- Verifies token availability  
- Verifies token expiry  

---

# 📦 6. Read Full Session State

```js
oauth.getSessionState();
```

### Returns:
```js
{
  tokens: { access_token, refresh_token },
  expiresAt: 1730000000000,
  user: {...}
}
```

---

# 🔁 7. Refresh Access Tokens (Automatic & Manual)

### Manual:
```js
await oauth.refresh();
```

### Automatic:
Enabled when:

```js
autoRefresh: true
```

Package automatically:
- Detects token expiry  
- Uses refresh token  
- Emits `tokenRefresh` event  

---

# 🚪 8. Logout

```js
await oauth.logout({ revokeTokens: false });
```

### Package does:
- Clears tokens  
- Clears session state  
- Optionally revokes tokens on server  

---

# 📡 9. Event Listeners

```js
oauth.on("error", (err) => {});
oauth.on("tokenRefresh", (tokens) => {});
oauth.on("stateChange", ({ event, data }) => {});
```

### Events emitted by the package:

| Event | Fired When |
|-------|------------|
| `error` | Any OAuth error occurs |
| `tokenRefresh` | Access token refreshed |
| `stateChange` | Login, logout, token change |

---

# 🧠 Summary of All Package Features

| Feature | Provided by Package |
|---------|---------------------|
| PKCE Support | ✅ |
| Popup Login | ✅ |
| Redirect Flow | ✅ |
| Automatic Token Refresh | ✅ |
| Token Storage | ✅ |
| Session Management | ✅ |
| User Info Fetcher | ✅ |
| Event System | ✅ |
| State Validation | ✅ |
| Token Expiry Handling | ✅ |
| Logout + Optional Revoke | ✅ |

---

# 📝 License  
MIT © Zenuxs Team
