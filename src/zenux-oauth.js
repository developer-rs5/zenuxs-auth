/**
 * ZenuxOAuth - Enhanced OAuth 2.0 PKCE Client Library
 * @version 2.0.0
 * @license MIT
 */

class ZenuxOAuthError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ZenuxOAuthError';
        this.code = code;
        this.details = details;
        this.timestamp = new Date().toISOString();
    }

    toJSON() {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            details: this.details,
            timestamp: this.timestamp
        };
    }
}

class ZenuxOAuth {
    constructor(config = {}) {
        this.validateConfig(config);

        this.config = {
            // Core OAuth settings
            authServer: config.authServer || 'https://api.auth.zenuxs.in',
            clientId: config.clientId,
            redirectUri: config.redirectUri || this.getDefaultRedirectUri(),
            scopes: config.scopes || 'openid profile email',
            
            // Authorization endpoint customization
            authorizeEndpoint: config.authorizeEndpoint || '/oauth/authorize',
            tokenEndpoint: config.tokenEndpoint || '/oauth/token',
            userinfoEndpoint: config.userinfoEndpoint || '/oauth/userinfo',
            revokeEndpoint: config.revokeEndpoint || '/oauth/revoke',
            
            // Storage options
            storage: config.storage || 'sessionStorage', // 'localStorage' or 'sessionStorage'
            storagePrefix: config.storagePrefix || 'zenux_oauth_',
            
            // Security options
            usePKCE: config.usePKCE !== false, // Enable PKCE by default
            useCSRF: config.useCSRF !== false, // Enable CSRF protection
            validateState: config.validateState !== false,
            
            // Token management
            autoRefresh: config.autoRefresh !== false,
            refreshThreshold: config.refreshThreshold || 300, // Refresh 5 min before expiry
            
            // Popup settings
            popupWidth: config.popupWidth || 600,
            popupHeight: config.popupHeight || 700,
            
            // Custom parameters
            extraAuthParams: config.extraAuthParams || {},
            extraTokenParams: config.extraTokenParams || {},
            
            // Callbacks
            onBeforeLogin: config.onBeforeLogin || null,
            onAfterLogin: config.onAfterLogin || null,
            onBeforeLogout: config.onBeforeLogout || null,
            onAfterLogout: config.onAfterLogout || null,
            
            // Debug mode
            debug: config.debug || false,
            
            // Custom fetch function (for adding interceptors, etc)
            fetchFunction: config.fetchFunction || (typeof fetch !== 'undefined' ? fetch.bind(window) : null)
        };

        this.session = {
            codeVerifier: null,
            state: null,
            tokens: null,
            csrfToken: null,
            nonce: null
        };

        this.eventHandlers = {
            login: [],
            logout: [],
            tokenRefresh: [],
            error: [],
            tokenExpired: [],
            stateChange: []
        };

        this._refreshInterval = null;
        this._pendingRequests = new Map();

        this.init();
        
        // Expose instance globally for callback page access (only in browser)
        if (typeof window !== 'undefined') {
            window.ZenuxOAuthInstance = this;
        }
    }

    // ==================== INITIALIZATION ====================

    init() {
        this.debugLog('Initializing ZenuxOAuth', this.config);
        this.loadTokens();
        
        if (this.config.autoRefresh && typeof window !== 'undefined') {
            this.setupAutoRefresh();
        }

        // Setup visibility change listener for token refresh
        if (typeof document !== 'undefined') {
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden && this.isAuthenticated()) {
                    this.checkAndRefreshToken();
                }
            });
        }
    }

    // ==================== CONFIGURATION ====================

    validateConfig(config) {
        const errors = [];
        
        if (!config.clientId) {
            errors.push('clientId is required');
        }
        
        if (config.redirectUri && !this.isValidUrl(config.redirectUri)) {
            errors.push('redirectUri must be a valid URL');
        }
        
        if (config.authServer && !this.isValidUrl(config.authServer)) {
            errors.push('authServer must be a valid URL');
        }
        
        if (config.storage && !['localStorage', 'sessionStorage'].includes(config.storage)) {
            errors.push('storage must be either "localStorage" or "sessionStorage"');
        }
        
        if (config.refreshThreshold && (config.refreshThreshold < 0 || config.refreshThreshold > 3600)) {
            errors.push('refreshThreshold must be between 0 and 3600 seconds');
        }
        
        if (errors.length > 0) {
            throw new ZenuxOAuthError(
                `Invalid configuration: ${errors.join(', ')}`,
                'INVALID_CONFIG',
                { errors }
            );
        }
    }

    isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    getDefaultRedirectUri() {
        if (typeof window !== 'undefined' && window.location) {
            return `${window.location.origin}/callback.html`;
        }
        return 'http://localhost/callback.html';
    }

    // Update configuration at runtime
    updateConfig(newConfig) {
        Object.assign(this.config, newConfig);
        this.debugLog('Configuration updated', newConfig);
    }

    // ==================== EVENT SYSTEM ====================

    on(event, handler) {
        if (!this.eventHandlers[event]) {
            this.eventHandlers[event] = [];
        }
        this.eventHandlers[event].push(handler);
        return this;
    }

    off(event, handler) {
        if (this.eventHandlers[event]) {
            if (handler) {
                this.eventHandlers[event] = this.eventHandlers[event].filter(h => h !== handler);
            } else {
                this.eventHandlers[event] = [];
            }
        }
        return this;
    }

    emit(event, data) {
        this.debugLog(`Event emitted: ${event}`, data);
        
        if (this.eventHandlers[event]) {
            this.eventHandlers[event].forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    console.error(`Error in ${event} handler:`, error);
                }
            });
        }

        // Also emit stateChange for any event
        if (event !== 'stateChange') {
            this.emit('stateChange', { event, data, timestamp: Date.now() });
        }
    }

    // ==================== PKCE HELPERS ====================

    generateRandomString(length = 128) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        const randomValues = new Uint8Array(length);
        
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(randomValues);
        } else {
            for (let i = 0; i < length; i++) {
                randomValues[i] = Math.floor(Math.random() * 256);
            }
        }
        
        return Array.from(randomValues, byte => charset[byte % charset.length]).join('');
    }

    async sha256(plain) {
        if (typeof process !== 'undefined' && process.versions && process.versions.node) {
            const crypto = require('crypto');
            const hash = crypto.createHash('sha256').update(plain).digest('base64');
            return hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }
        
        if (typeof crypto !== 'undefined' && crypto.subtle) {
            const encoder = new TextEncoder();
            const data = encoder.encode(plain);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode(...new Uint8Array(hash)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }
        
        throw new ZenuxOAuthError(
            'SHA-256 not supported in this environment',
            'CRYPTO_NOT_SUPPORTED'
        );
    }

    // ==================== AUTHENTICATION FLOW ====================

    async login(options = {}) {
        try {
            // Execute before login callback
            if (this.config.onBeforeLogin) {
                await this.config.onBeforeLogin();
            }

            this.debugLog('Starting OAuth flow', options);

            // Generate PKCE parameters
            if (this.config.usePKCE) {
                this.session.codeVerifier = this.generateRandomString(128);
                this.session.codeChallenge = await this.sha256(this.session.codeVerifier);
                this.setStorage('code_verifier', this.session.codeVerifier);
            }

            // Generate state parameter
            this.session.state = this.generateRandomString(32);
            this.setStorage('state', this.session.state);

            // Generate nonce for ID token validation
            this.session.nonce = this.generateRandomString(32);
            this.setStorage('nonce', this.session.nonce);

            // Generate CSRF token
            if (this.config.useCSRF) {
                this.session.csrfToken = this.generateRandomString(32);
                this.setStorage('csrf_token', this.session.csrfToken);
            }

            // Build authorization URL
            const params = new URLSearchParams({
                client_id: this.config.clientId,
                redirect_uri: options.redirectUri || this.config.redirectUri,
                scope: options.scopes || this.config.scopes,
                response_type: 'code',
                state: this.session.state,
                nonce: this.session.nonce,
                ...this.config.extraAuthParams,
                ...(options.extraParams || {})
            });

            if (this.config.usePKCE) {
                params.append('code_challenge', this.session.codeChallenge);
                params.append('code_challenge_method', 'S256');
            }

            const authUrl = `${this.config.authServer}${this.config.authorizeEndpoint}?${params.toString()}`;
            
            this.debugLog('Authorization URL built', authUrl);

            // Handle different login modes
            if (options.popup && typeof window !== 'undefined') {
                return this.loginWithPopup(authUrl, options);
            } else if (options.silent) {
                return this.loginSilent(authUrl, options);
            } else if (typeof window !== 'undefined') {
                window.location.href = authUrl;
                return null;
            } else {
                return authUrl;
            }
        } catch (error) {
            this.debugLog('Login error', error);
            this.emit('error', error);
            throw error;
        }
    }

    loginWithPopup(authUrl, options = {}) {
        return new Promise((resolve, reject) => {
            if (typeof window === 'undefined') {
                const error = new ZenuxOAuthError(
                    'Popup login only available in browser',
                    'POPUP_NOT_AVAILABLE'
                );
                this.emit('error', error);
                reject(error);
                return;
            }

            const width = options.popupWidth || this.config.popupWidth;
            const height = options.popupHeight || this.config.popupHeight;
            const left = (window.screen.width - width) / 2;
            const top = (window.screen.height - height) / 2;

            const popup = window.open(
                authUrl,
                options.popupName || 'zenux_oauth',
                `width=${width},height=${height},left=${left},top=${top},scrollbars=yes,resizable=yes`
            );

            if (!popup) {
                const error = new ZenuxOAuthError(
                    'Popup blocked. Please allow popups and try again.',
                    'POPUP_BLOCKED'
                );
                this.emit('error', error);
                reject(error);
                return;
            }

            const timeout = setTimeout(() => {
                cleanup();
                reject(new ZenuxOAuthError('Login timeout', 'LOGIN_TIMEOUT'));
            }, options.timeout || 300000); // 5 minute default timeout

            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    cleanup();
                    const tokens = this.getTokens();
                    if (tokens) {
                        resolve(tokens);
                    } else {
                        reject(new ZenuxOAuthError('Authentication cancelled', 'AUTH_CANCELLED'));
                    }
                }
            }, 1000);

            const messageHandler = async (event) => {
                if (event.data && event.data.type === 'zenux_oauth_success') {
                    cleanup();
                    this.session.tokens = event.data.tokens;
                    this.setStorage('tokens', JSON.stringify(this.session.tokens));
                    popup.close();
                    
                    if (this.config.onAfterLogin) {
                        await this.config.onAfterLogin(this.session.tokens);
                    }
                    
                    this.emit('login', this.session.tokens);
                    resolve(this.session.tokens);
                } else if (event.data && event.data.type === 'zenux_oauth_error') {
                    cleanup();
                    popup.close();
                    const error = new ZenuxOAuthError(
                        event.data.error,
                        event.data.code || 'AUTH_ERROR',
                        event.data.details
                    );
                    this.emit('error', error);
                    reject(error);
                }
            };

            const cleanup = () => {
                clearInterval(checkClosed);
                clearTimeout(timeout);
                window.removeEventListener('message', messageHandler);
            };

            window.addEventListener('message', messageHandler);
        });
    }

    loginSilent(authUrl, options = {}) {
        return new Promise((resolve, reject) => {
            if (typeof document === 'undefined') {
                reject(new ZenuxOAuthError('Silent login only available in browser', 'SILENT_NOT_AVAILABLE'));
                return;
            }

            const iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.src = authUrl;

            const timeout = setTimeout(() => {
                cleanup();
                reject(new ZenuxOAuthError('Silent login timeout', 'SILENT_TIMEOUT'));
            }, options.timeout || 60000);

            const messageHandler = (event) => {
                if (event.data && event.data.type === 'zenux_oauth_success') {
                    cleanup();
                    this.session.tokens = event.data.tokens;
                    this.setStorage('tokens', JSON.stringify(this.session.tokens));
                    this.emit('login', this.session.tokens);
                    resolve(this.session.tokens);
                } else if (event.data && event.data.type === 'zenux_oauth_error') {
                    cleanup();
                    reject(new ZenuxOAuthError(event.data.error, 'SILENT_ERROR'));
                }
            };

            const cleanup = () => {
                clearTimeout(timeout);
                window.removeEventListener('message', messageHandler);
                if (iframe.parentNode) {
                    iframe.parentNode.removeChild(iframe);
                }
            };

            window.addEventListener('message', messageHandler);
            document.body.appendChild(iframe);
        });
    }

    async handleCallback(callbackUrl = null) {
        try {
            this.debugLog('Handling OAuth callback');

            const url = callbackUrl || (typeof window !== 'undefined' ? window.location.href : null);
            
            if (!url) {
                throw new ZenuxOAuthError('No callback URL provided', 'NO_CALLBACK_URL');
            }

            const urlObj = new URL(url);
            const params = new URLSearchParams(urlObj.search);

            const code = params.get('code');
            const state = params.get('state');
            const error = params.get('error');
            const errorDescription = params.get('error_description');

            this.debugLog('Callback parameters', { code: !!code, state, error });

            if (error) {
                throw new ZenuxOAuthError(
                    errorDescription || error,
                    'OAUTH_ERROR',
                    { error, errorDescription }
                );
            }

            if (!code) {
                throw new ZenuxOAuthError('No authorization code received', 'NO_AUTH_CODE');
            }

            // Validate state
            if (this.config.validateState) {
                const storedState = this.getStorage('state');
                if (state !== storedState) {
                    throw new ZenuxOAuthError('State parameter mismatch', 'STATE_MISMATCH');
                }
            }

            // Get code verifier
            const codeVerifier = this.getStorage('code_verifier');
            if (this.config.usePKCE && !codeVerifier) {
                throw new ZenuxOAuthError('No code verifier found', 'NO_CODE_VERIFIER');
            }

            // Exchange code for tokens
            const tokens = await this.exchangeCodeForTokens(code, codeVerifier);
            
            this.session.tokens = tokens;
            this.setStorage('tokens', JSON.stringify(tokens));
            
            // Cleanup temporary storage
            this.clearStorage('code_verifier');
            this.clearStorage('state');
            this.clearStorage('nonce');
            this.clearStorage('csrf_token');
            
            // Clean URL
            if (typeof history !== 'undefined' && history.replaceState) {
                history.replaceState({}, document.title, urlObj.pathname);
            }

            if (this.config.onAfterLogin) {
                await this.config.onAfterLogin(tokens);
            }

            this.emit('login', tokens);
            return tokens;
        } catch (error) {
            this.debugLog('Callback error', error);
            this.emit('error', error);
            throw error;
        }
    }

    async exchangeCodeForTokens(code, codeVerifier) {
        const tokenData = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: this.config.redirectUri,
            client_id: this.config.clientId,
            ...this.config.extraTokenParams
        });

        if (this.config.usePKCE && codeVerifier) {
            tokenData.append('code_verifier', codeVerifier);
        }

        const response = await this.config.fetchFunction(`${this.config.authServer}${this.config.tokenEndpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: tokenData
        });

        if (!response.ok) {
            let errorDetails;
            try {
                errorDetails = await response.json();
            } catch {
                errorDetails = await response.text();
            }

            throw new ZenuxOAuthError(
                `Token exchange failed: ${response.status}`,
                'TOKEN_EXCHANGE_FAILED',
                { status: response.status, response: errorDetails }
            );
        }

        const tokens = await response.json();
        
        if (tokens.expires_in) {
            tokens.expires_at = Date.now() + (tokens.expires_in * 1000);
        }
        
        return tokens;
    }

    // ==================== TOKEN MANAGEMENT ====================

    getTokens() {
        if (this.session.tokens) {
            return this.session.tokens;
        }

        const storedTokens = this.getStorage('tokens');
        if (storedTokens) {
            try {
                this.session.tokens = JSON.parse(storedTokens);
                return this.session.tokens;
            } catch (e) {
                this.clearStorage('tokens');
            }
        }

        return null;
    }

    loadTokens() {
        this.getTokens();
    }

    isAuthenticated() {
        const tokens = this.getTokens();
        return !!(tokens && tokens.access_token && !this.isTokenExpired());
    }

    isTokenExpired() {
        const tokens = this.getTokens();
        if (!tokens?.access_token) return true;
        
        if (tokens.expires_at) {
            const isExpired = Date.now() >= tokens.expires_at;
            if (isExpired) {
                this.emit('tokenExpired', tokens);
            }
            return isExpired;
        }
        
        return false;
    }

    async refreshTokens() {
        const refreshPromise = this._pendingRequests.get('refresh');
        if (refreshPromise) {
            return refreshPromise;
        }

        const promise = this._refreshTokensInternal();
        this._pendingRequests.set('refresh', promise);

        try {
            const result = await promise;
            this._pendingRequests.delete('refresh');
            return result;
        } catch (error) {
            this._pendingRequests.delete('refresh');
            throw error;
        }
    }

    async _refreshTokensInternal() {
        try {
            const tokens = this.getTokens();
            if (!tokens?.refresh_token) {
                throw new ZenuxOAuthError('No refresh token available', 'NO_REFRESH_TOKEN');
            }

            this.debugLog('Refreshing tokens');

            const response = await this.config.fetchFunction(
                `${this.config.authServer}${this.config.tokenEndpoint}`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'
                    },
                    body: new URLSearchParams({
                        grant_type: 'refresh_token',
                        refresh_token: tokens.refresh_token,
                        client_id: this.config.clientId,
                        ...this.config.extraTokenParams
                    })
                }
            );

            if (!response.ok) {
                throw new ZenuxOAuthError(
                    'Token refresh failed',
                    'TOKEN_REFRESH_FAILED',
                    { status: response.status }
                );
            }

            const newTokens = await response.json();
            
            if (newTokens.expires_in) {
                newTokens.expires_at = Date.now() + (newTokens.expires_in * 1000);
            }
            
            if (!newTokens.refresh_token && tokens.refresh_token) {
                newTokens.refresh_token = tokens.refresh_token;
            }

            this.session.tokens = newTokens;
            this.setStorage('tokens', JSON.stringify(this.session.tokens));
            
            this.emit('tokenRefresh', newTokens);
            return newTokens;
        } catch (error) {
            this.debugLog('Token refresh error', error);
            this.emit('error', error);
            
            if (error.code === 'TOKEN_REFRESH_FAILED') {
                this.logout();
            }
            
            throw error;
        }
    }

    async checkAndRefreshToken() {
        if (!this.isAuthenticated()) return;

        const tokens = this.getTokens();
        if (tokens.expires_at) {
            const timeUntilExpiry = (tokens.expires_at - Date.now()) / 1000;
            if (timeUntilExpiry < this.config.refreshThreshold) {
                try {
                    await this.refreshTokens();
                } catch (error) {
                    this.debugLog('Auto refresh failed', error);
                }
            }
        }
    }

    setupAutoRefresh() {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
        }

        this._refreshInterval = setInterval(() => {
            this.checkAndRefreshToken();
        }, 60000); // Check every minute
    }

    async revokeToken(token = null, tokenType = 'access_token') {
        try {
            const tokens = this.getTokens();
            const tokenToRevoke = token || tokens?.[tokenType];

            if (!tokenToRevoke) {
                throw new ZenuxOAuthError(`No ${tokenType} available to revoke`, 'NO_TOKEN');
            }

            const response = await this.config.fetchFunction(
                `${this.config.authServer}${this.config.revokeEndpoint}`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({
                        token: tokenToRevoke,
                        token_type_hint: tokenType,
                        client_id: this.config.clientId
                    })
                }
            );

            if (!response.ok) {
                throw new ZenuxOAuthError('Token revocation failed', 'REVOKE_FAILED');
            }

            return true;
        } catch (error) {
            this.debugLog('Token revocation error', error);
            throw error;
        }
    }

    // ==================== USER INFO ====================

    async getUserInfo() {
        try {
            const tokens = this.getTokens();
            if (!tokens?.access_token) {
                throw new ZenuxOAuthError('No access token available', 'NO_ACCESS_TOKEN');
            }

            const endpoints = [
                `${this.config.authServer}${this.config.userinfoEndpoint}`,
                `${this.config.authServer}/userinfo`,
                `${this.config.authServer}/api/userinfo`
            ];

            let lastError;
            for (const endpoint of endpoints) {
                try {
                    const response = await this.config.fetchFunction(endpoint, {
                        headers: {
                            'Authorization': `Bearer ${tokens.access_token}`,
                            'Accept': 'application/json'
                        }
                    });

                    if (response.ok) {
                        return await response.json();
                    }

                    if (response.status !== 404) {
                        lastError = new ZenuxOAuthError(
                            `UserInfo request failed: ${response.status}`,
                            'USERINFO_FAILED'
                        );
                        break;
                    }
                } catch (error) {
                    lastError = error;
                    continue;
                }
            }

            if (tokens.id_token) {
                const userInfo = this.decodeJWT(tokens.id_token);
                if (userInfo) return userInfo;
            }

            throw lastError || new ZenuxOAuthError('Could not retrieve user info', 'USERINFO_FAILED');
        } catch (error) {
            this.debugLog('Get user info error', error);
            this.emit('error', error);
            throw error;
        }
    }

    // ==================== LOGOUT ====================

    async logout(options = {}) {
        try {
            if (this.config.onBeforeLogout) {
                await this.config.onBeforeLogout();
            }

            const hadTokens = this.isAuthenticated();

            if (options.revokeTokens && this.session.tokens) {
                try {
                    await this.revokeToken(this.session.tokens.access_token, 'access_token');
                    if (this.session.tokens.refresh_token) {
                        await this.revokeToken(this.session.tokens.refresh_token, 'refresh_token');
                    }
                } catch (error) {
                    this.debugLog('Token revocation during logout failed', error);
                }
            }

            this.clearStorage('tokens');
            this.clearStorage('code_verifier');
            this.clearStorage('state');
            this.clearStorage('nonce');
            this.clearStorage('csrf_token');
            
            this.session = {
                codeVerifier: null,
                state: null,
                tokens: null,
                csrfToken: null,
                nonce: null
            };

            if (this.config.onAfterLogout) {
                await this.config.onAfterLogout();
            }

            if (hadTokens) {
                this.emit('logout');
            }

            return true;
        } catch (error) {
            this.debugLog('Logout error', error);
            this.emit('error', error);
            throw error;
        }
    }

    // ==================== AUTHENTICATED REQUESTS ====================

    getAuthenticatedFetch() {
        return async (url, options = {}) => {
            if (this.isTokenExpired() && this.getTokens()?.refresh_token) {
                try {
                    await this.refreshTokens();
                } catch (error) {
                    throw new ZenuxOAuthError(
                        'Unable to refresh tokens for request',
                        'AUTH_REQUEST_FAILED',
                        { originalError: error }
                    );
                }
            }
            
            const tokens = this.getTokens();
            if (!tokens?.access_token) {
                throw new ZenuxOAuthError('No access token available', 'NO_ACCESS_TOKEN');
            }

            const headers = {
                'Authorization': `Bearer ${tokens.access_token}`,
                'Accept': 'application/json',
                ...options.headers
            };
            
            return this.config.fetchFunction(url, { ...options, headers });
        };
    }

    // ==================== UTILITIES ====================

    decodeJWT(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonPayload = decodeURIComponent(
                atob(base64).split('').map(c => 
                    '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
                ).join('')
            );
            return JSON.parse(jsonPayload);
        } catch (error) {
            this.debugLog('JWT decode error', error);
            return null;
        }
    }

    getStorage(key) {
        if (typeof window === 'undefined') return null;
        
        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            return storage.getItem(this.config.storagePrefix + key);
        } catch (e) {
            this.debugLog('Storage get failed', e);
            return null;
        }
    }

    setStorage(key, value) {
        if (typeof window === 'undefined') return;
        
        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.setItem(this.config.storagePrefix + key, value);
        } catch (e) {
            this.debugLog('Storage set failed', e);
        }
    }

    clearStorage(key) {
        if (typeof window === 'undefined') return;
        
        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.removeItem(this.config.storagePrefix + key);
        } catch (e) {
            this.debugLog('Storage clear failed', e);
        }
    }

    debugLog(message, data = null) {
        if (!this.config.debug) return;
        
        const timestamp = new Date().toISOString();
        console.log(`[ZenuxOAuth ${timestamp}]`, message, data || '');
    }

    // ==================== ADVANCED FEATURES ====================

    // Get authorization URL without redirecting
    async getAuthorizationUrl(options = {}) {
        if (this.config.usePKCE) {
            this.session.codeVerifier = this.generateRandomString(128);
            this.session.codeChallenge = await this.sha256(this.session.codeVerifier);
        }

        this.session.state = this.generateRandomString(32);
        this.session.nonce = this.generateRandomString(32);

        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: options.redirectUri || this.config.redirectUri,
            scope: options.scopes || this.config.scopes,
            response_type: 'code',
            state: this.session.state,
            nonce: this.session.nonce,
            ...this.config.extraAuthParams,
            ...(options.extraParams || {})
        });

        if (this.config.usePKCE) {
            params.append('code_challenge', this.session.codeChallenge);
            params.append('code_challenge_method', 'S256');
        }

        return {
            url: `${this.config.authServer}${this.config.authorizeEndpoint}?${params.toString()}`,
            state: this.session.state,
            codeVerifier: this.session.codeVerifier,
            nonce: this.session.nonce
        };
    }

    // Get token info/introspection
    async introspectToken(token = null) {
        try {
            const tokens = this.getTokens();
            const tokenToIntrospect = token || tokens?.access_token;

            if (!tokenToIntrospect) {
                throw new ZenuxOAuthError('No token to introspect', 'NO_TOKEN');
            }

            const response = await this.config.fetchFunction(
                `${this.config.authServer}/oauth/introspect`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({
                        token: tokenToIntrospect,
                        client_id: this.config.clientId
                    })
                }
            );

            if (!response.ok) {
                throw new ZenuxOAuthError('Token introspection failed', 'INTROSPECT_FAILED');
            }

            return await response.json();
        } catch (error) {
            this.debugLog('Token introspection error', error);
            throw error;
        }
    }

    // Get current session state
    getSessionState() {
        return {
            isAuthenticated: this.isAuthenticated(),
            tokens: this.getTokens(),
            hasRefreshToken: !!this.getTokens()?.refresh_token,
            isExpired: this.isTokenExpired(),
            expiresAt: this.getTokens()?.expires_at,
            timeUntilExpiry: this.getTokens()?.expires_at 
                ? Math.max(0, this.getTokens().expires_at - Date.now()) 
                : null
        };
    }

    // Export session for transfer (e.g., between tabs)
    exportSession() {
        return {
            tokens: this.session.tokens,
            config: {
                clientId: this.config.clientId,
                authServer: this.config.authServer,
                scopes: this.config.scopes
            },
            timestamp: Date.now()
        };
    }

    // Import session from another source
    importSession(sessionData) {
        if (!sessionData || !sessionData.tokens) {
            throw new ZenuxOAuthError('Invalid session data', 'INVALID_SESSION');
        }

        this.session.tokens = sessionData.tokens;
        this.setStorage('tokens', JSON.stringify(this.session.tokens));
        this.emit('login', this.session.tokens);
    }

    // Cleanup and destroy instance
    destroy() {
        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
            this._refreshInterval = null;
        }
        
        this._pendingRequests.clear();
        
        this.eventHandlers = {
            login: [],
            logout: [],
            tokenRefresh: [],
            error: [],
            tokenExpired: [],
            stateChange: []
        };

        this.debugLog('ZenuxOAuth instance destroyed');
    }
}

// ==================== FACTORY & HELPERS ====================

// Factory function for easier instantiation
ZenuxOAuth.create = function(config) {
    return new ZenuxOAuth(config);
};

// Singleton pattern helper
ZenuxOAuth.instance = null;
ZenuxOAuth.getInstance = function(config) {
    if (!ZenuxOAuth.instance) {
        ZenuxOAuth.instance = new ZenuxOAuth(config);
    }
    return ZenuxOAuth.instance;
};

ZenuxOAuth.destroyInstance = function() {
    if (ZenuxOAuth.instance) {
        ZenuxOAuth.instance.destroy();
        ZenuxOAuth.instance = null;
    }
};

// Export error class
ZenuxOAuth.Error = ZenuxOAuthError;

// Version
ZenuxOAuth.VERSION = '2.0.0';

// ==================== UMD EXPORT ====================

(function (global, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        global.ZenuxOAuth = factory();
    }
}(typeof window !== 'undefined' ? window : this, function () {
    return ZenuxOAuth;
}));