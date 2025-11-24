/**
 * ZenuxOAuth - Enhanced OAuth 2.0 PKCE Client Library
 * @version 2.2.0
 * @license MIT
 * @environment Web, React, Node.js
 */

// Environment detection utilities
const Environment = {
    isBrowser: typeof window !== 'undefined' && typeof document !== 'undefined',
    isReactNative: typeof navigator !== 'undefined' && navigator.product === 'ReactNative',
    isNode: typeof process !== 'undefined' && process.versions && process.versions.node,
    isWebWorker: typeof importScripts !== 'undefined',
    getEnvironment() {
        if (this.isReactNative) return 'react-native';
        if (this.isNode) return 'node';
        if (this.isWebWorker) return 'web-worker';
        if (this.isBrowser) return 'browser';
        return 'unknown';
    }
};

class ZenuxOAuthError extends Error {
    constructor(message, code, details = {}) {
        super(message);
        this.name = 'ZenuxOAuthError';
        this.code = code;
        this.details = details;
        this.timestamp = new Date().toISOString();
        this.environment = Environment.getEnvironment();
    }

    toJSON() {
        return {
            name: this.name,
            code: this.code,
            message: this.message,
            details: this.details,
            timestamp: this.timestamp,
            environment: this.environment
        };
    }
}

class ZenuxOAuth {
    constructor(config = {}) {
        this.validateConfig(config);

        // Default fetch function based on environment
        let defaultFetch = null;
        if (typeof fetch !== 'undefined') {
            defaultFetch = Environment.isBrowser ? fetch.bind(window) : fetch;
        } else {
            throw new ZenuxOAuthError(
                'Fetch is not available in this environment. Please provide a fetchFunction',
                'FETCH_UNAVAILABLE'
            );
        }

        this.config = {
            authServer: config.authServer || 'https://api.auth.zenuxs.in',
            clientId: config.clientId,
            redirectUri: config.redirectUri || this.getDefaultRedirectUri(),
            scopes: config.scopes || 'openid profile email',
            authorizeEndpoint: config.authorizeEndpoint || '/oauth/authorize',
            tokenEndpoint: config.tokenEndpoint || '/oauth/token',
            userinfoEndpoint: config.userinfoEndpoint || '/oauth/userinfo',
            revokeEndpoint: config.revokeEndpoint || '/oauth/revoke',
            storage: config.storage || (Environment.isBrowser ? 'sessionStorage' : 'memory'),
            storagePrefix: config.storagePrefix || 'zenux_oauth_',
            usePKCE: config.usePKCE !== false,
            useCSRF: config.useCSRF !== false && Environment.isBrowser,
            validateState: config.validateState !== false,
            autoRefresh: config.autoRefresh !== false && Environment.isBrowser,
            refreshThreshold: config.refreshThreshold || 300,
            popupWidth: config.popupWidth || 600,
            popupHeight: config.popupHeight || 700,
            extraAuthParams: config.extraAuthParams || {},
            extraTokenParams: config.extraTokenParams || {},
            onBeforeLogin: config.onBeforeLogin || null,
            onAfterLogin: config.onAfterLogin || null,
            onBeforeLogout: config.onBeforeLogout || null,
            onAfterLogout: config.onAfterLogout || null,
            debug: config.debug || false,
            fetchFunction: config.fetchFunction || defaultFetch,
            environment: Environment.getEnvironment()
        };

        this.session = {
            codeVerifier: null,
            state: null,
            tokens: null,
            csrfToken: null,
            nonce: null
        };

        // Memory storage for Node.js environment
        this.memoryStorage = new Map();

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

        // Fixed: Added the missing init method
        this.init();

        if (Environment.isBrowser && !Environment.isReactNative) {
            window.ZenuxOAuthInstance = this;
        }
    }

    // Fixed: Added the missing init method
    init() {
        this.debugLog('Initializing ZenuxOAuth');
        this.setupAutoRefresh();
        
        // Load any existing tokens from storage
        this.loadTokens();
        
        this.debugLog('ZenuxOAuth initialized successfully', {
            environment: Environment.getEnvironment(),
            clientId: this.config.clientId,
            authServer: this.config.authServer
        });
    }

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

        if (Environment.isBrowser && config.storage && !['localStorage', 'sessionStorage', 'memory'].includes(config.storage)) {
            errors.push('storage must be either "localStorage", "sessionStorage", or "memory"');
        }

        if (!Environment.isBrowser && config.storage && config.storage !== 'memory') {
            errors.push('Only "memory" storage is supported in non-browser environments');
        }

        if (config.refreshThreshold && (config.refreshThreshold < 0 || config.refreshThreshold > 3600)) {
            errors.push('refreshThreshold must be between 0 and 3600 seconds');
        }

        if (!config.fetchFunction && typeof fetch === 'undefined') {
            errors.push('fetchFunction is required as fetch is not available in this environment');
        }

        if (errors.length > 0) {
            throw new ZenuxOAuthError(
                `Invalid configuration: ${errors.join(', ')}`,
                'INVALID_CONFIG',
                { errors, environment: Environment.getEnvironment() }
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
        if (Environment.isBrowser && window.location) {
            return `${window.location.origin}/callback.html`;
        }
        return 'http://localhost/callback.html';
    }

    updateConfig(newConfig) {
        Object.assign(this.config, newConfig);
        this.debugLog('Configuration updated', newConfig);
    }

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

        if (event !== 'stateChange') {
            this.emit('stateChange', { event, data, timestamp: Date.now() });
        }
    }

    generateRandomString(length = 128) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        
        if (Environment.isNode) {
            // Use crypto module in Node.js
            if (typeof crypto !== 'undefined' && crypto.randomBytes) {
                return crypto.randomBytes(length)
                    .toString('base64')
                    .replace(/[+/=]/g, '')
                    .slice(0, length)
                    .split('')
                    .map(char => charset.charAt(char.charCodeAt(0) % charset.length))
                    .join('');
            }
        }

        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const randomValues = new Uint8Array(length);
            crypto.getRandomValues(randomValues);
            return Array.from(randomValues, byte => charset[byte % charset.length]).join('');
        }

        // Fallback for environments without crypto
        let result = '';
        for (let i = 0; i < length; i++) {
            result += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        return result;
    }

    async sha256(plain) {
        // Browser environment - use Web Crypto API
        if (typeof crypto !== 'undefined' && crypto.subtle) {
            const encoder = new TextEncoder();
            const data = encoder.encode(plain);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return btoa(String.fromCharCode(...new Uint8Array(hash)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }
        
        // Node.js environment with Web Crypto API (Node 15+)
        if (Environment.isNode && typeof crypto !== 'undefined' && crypto.subtle) {
            const encoder = new TextEncoder();
            const data = encoder.encode(plain);
            const hash = await crypto.subtle.digest('SHA-256', data);
            return Buffer.from(hash).toString('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
        }

        throw new ZenuxOAuthError(
            'SHA-256 not supported in this environment. Web Crypto API is required.',
            'CRYPTO_NOT_SUPPORTED'
        );
    }

    async login(options = {}) {
        try {
            if (this.config.onBeforeLogin) {
                await this.config.onBeforeLogin();
            }

            this.debugLog('Starting OAuth flow', { ...options, environment: Environment.getEnvironment() });

            // For non-browser environments, return authorization URL
            if (!Environment.isBrowser) {
                const authData = await this.getAuthorizationUrl(options);
                return {
                    type: 'authorization_url',
                    url: authData.url,
                    state: authData.state,
                    codeVerifier: authData.codeVerifier
                };
            }

            if (this.config.usePKCE) {
                this.session.codeVerifier = this.generateRandomString(128);
                this.session.codeChallenge = await this.sha256(this.session.codeVerifier);
                this.setStorage('code_verifier', this.session.codeVerifier);
            }

            this.session.state = this.generateRandomString(32);
            this.setStorage('state', this.session.state);

            this.session.nonce = this.generateRandomString(32);
            this.setStorage('nonce', this.session.nonce);

            if (this.config.useCSRF) {
                this.session.csrfToken = this.generateRandomString(32);
                this.setStorage('csrf_token', this.session.csrfToken);
            }

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

            if (options.popup) {
                return this.loginWithPopup(authUrl, options);
            } else if (options.silent) {
                return this.loginSilent(authUrl, options);
            } else {
                window.location.href = authUrl;
                return null;
            }
        } catch (error) {
            this.debugLog('Login error', error);
            this.emit('error', error);
            throw error;
        }
    }

    loginWithPopup(authUrl, options = {}) {
        return new Promise((resolve, reject) => {
            if (!Environment.isBrowser) {
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
            }, options.timeout || 300000);

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
            if (!Environment.isBrowser || !document) {
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

            let url;
            if (callbackUrl) {
                url = callbackUrl;
            } else if (Environment.isBrowser) {
                url = window.location.href;
            } else {
                throw new ZenuxOAuthError(
                    'No callback URL provided and not in browser environment',
                    'NO_CALLBACK_URL'
                );
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

            if (this.config.validateState) {
                const storedState = this.getStorage('state');
                if (state !== storedState) {
                    throw new ZenuxOAuthError('State parameter mismatch', 'STATE_MISMATCH');
                }
            }

            const codeVerifier = this.getStorage('code_verifier');
            if (this.config.usePKCE && !codeVerifier) {
                throw new ZenuxOAuthError('No code verifier found', 'NO_CODE_VERIFIER');
            }

            const tokens = await this.exchangeCodeForTokens(code, codeVerifier);

            this.session.tokens = tokens;
            this.setStorage('tokens', JSON.stringify(tokens));

            this.clearStorage('code_verifier');
            this.clearStorage('state');
            this.clearStorage('nonce');
            this.clearStorage('csrf_token');

            if (Environment.isBrowser && typeof history !== 'undefined' && history.replaceState) {
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
        if (!this.config.fetchFunction) {
            throw new ZenuxOAuthError('Fetch function not available', 'FETCH_UNAVAILABLE');
        }

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
        if (!Environment.isBrowser) return;

        if (this._refreshInterval) {
            clearInterval(this._refreshInterval);
        }

        this._refreshInterval = setInterval(() => {
            this.checkAndRefreshToken();
        }, 60000);
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

    decodeJWT(token) {
        try {
            const base64Url = token.split('.')[1];
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            
            let jsonPayload;
            if (Environment.isNode && typeof Buffer !== 'undefined') {
                const buffer = Buffer.from(base64, 'base64');
                jsonPayload = buffer.toString('utf8');
            } else {
                jsonPayload = decodeURIComponent(
                    atob(base64).split('').map(c =>
                        '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)
                    ).join('')
                );
            }
            
            return JSON.parse(jsonPayload);
        } catch (error) {
            this.debugLog('JWT decode error', error);
            return null;
        }
    }

    getStorage(key) {
        const fullKey = this.config.storagePrefix + key;

        if (this.config.storage === 'memory') {
            return this.memoryStorage.get(fullKey) || null;
        }

        if (!Environment.isBrowser) return null;

        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            return storage.getItem(fullKey);
        } catch (e) {
            this.debugLog('Storage get failed', e);
            return null;
        }
    }

    setStorage(key, value) {
        const fullKey = this.config.storagePrefix + key;

        if (this.config.storage === 'memory') {
            this.memoryStorage.set(fullKey, value);
            return;
        }

        if (!Environment.isBrowser) return;

        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.setItem(fullKey, value);
        } catch (e) {
            this.debugLog('Storage set failed', e);
        }
    }

    clearStorage(key) {
        const fullKey = this.config.storagePrefix + key;

        if (this.config.storage === 'memory') {
            this.memoryStorage.delete(fullKey);
            return;
        }

        if (!Environment.isBrowser) return;

        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.removeItem(fullKey);
        } catch (e) {
            this.debugLog('Storage clear failed', e);
        }
    }

    debugLog(message, data = null) {
        if (!this.config.debug) return;

        const timestamp = new Date().toISOString();
        const env = Environment.getEnvironment();
        console.log(`[ZenuxOAuth ${timestamp} ${env}]`, message, data || '');
    }

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

    getSessionState() {
        const tokens = this.getTokens();
        return {
            isAuthenticated: this.isAuthenticated(),
            tokens: tokens,
            hasRefreshToken: !!tokens?.refresh_token,
            isExpired: this.isTokenExpired(),
            expiresAt: tokens?.expires_at,
            timeUntilExpiry: tokens?.expires_at
                ? Math.max(0, tokens.expires_at - Date.now())
                : null,
            environment: Environment.getEnvironment()
        };
    }

    exportSession() {
        return {
            tokens: this.session.tokens,
            config: {
                clientId: this.config.clientId,
                authServer: this.config.authServer,
                scopes: this.config.scopes
            },
            timestamp: Date.now(),
            environment: Environment.getEnvironment()
        };
    }

    importSession(sessionData) {
        if (!sessionData || !sessionData.tokens) {
            throw new ZenuxOAuthError('Invalid session data', 'INVALID_SESSION');
        }

        this.session.tokens = sessionData.tokens;
        this.setStorage('tokens', JSON.stringify(this.session.tokens));
        this.emit('login', this.session.tokens);
    }

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

// ==================== CALLBACK HANDLER (Browser Only) ====================

class ZenuxOAuthCallbackHandler {
    constructor(config = {}) {
        if (!Environment.isBrowser) {
            console.warn('ZenuxOAuthCallbackHandler is only available in browser environments');
            return;
        }

        this.config = {
            debug: config.debug || false,
            autoClose: config.autoClose !== false,
            autoCloseDelay: config.autoCloseDelay || 2000,
            homeUrl: config.homeUrl || '/',
            storagePrefix: config.storagePrefix || 'zenux_oauth_',
            successMessage: config.successMessage || 'Authentication successful!',
            errorMessage: config.errorMessage || 'Authentication failed.',
            ...config
        };

        this.elements = {};
        this.init();
    }

    init() {
        this.debugLog('Initializing callback handler');
        
        if (Environment.isBrowser && typeof document !== 'undefined') {
            this.setupDOM();
            this.handleCallback();
        } else {
            this.debugLog('Running in non-browser environment, callback handler disabled');
        }
    }

    setupDOM() {
        if (!document.getElementById('zenux-oauth-callback-container')) {
            const container = document.createElement('div');
            container.id = 'zenux-oauth-callback-container';
            container.innerHTML = this.getDefaultHTML();
            document.body.appendChild(container);
        }

        this.elements = {
            loading: document.getElementById('zenux-oauth-loading'),
            success: document.getElementById('zenux-oauth-success'),
            error: document.getElementById('zenux-oauth-error'),
            successMessage: document.getElementById('zenux-oauth-success-message'),
            errorMessage: document.getElementById('zenux-oauth-error-message'),
            debug: document.getElementById('zenux-oauth-debug')
        };
    }

    getDefaultHTML() {
        return `
            <style>
                .zenux-oauth-callback {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    padding: 20px;
                    margin: 0;
                }
                .zenux-oauth-container {
                    background: rgba(255, 255, 255, 0.1);
                    padding: 40px;
                    border-radius: 20px;
                    backdrop-filter: blur(15px);
                    text-align: center;
                    max-width: 500px;
                    width: 100%;
                    box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
                    border: 1px solid rgba(255, 255, 255, 0.18);
                }
                .zenux-oauth-spinner {
                    border: 4px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top: 4px solid white;
                    width: 50px;
                    height: 50px;
                    animation: zenux-spin 1s linear infinite;
                    margin: 0 auto 20px;
                }
                @keyframes zenux-spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                .zenux-oauth-success { color: #4ade80; }
                .zenux-oauth-error { color: #f87171; }
                .zenux-oauth-hidden { display: none; }
                .zenux-oauth-button {
                    background: white;
                    color: #667eea;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    cursor: pointer;
                    font-size: 16px;
                    font-weight: 600;
                    margin: 10px 5px;
                    transition: all 0.3s ease;
                    text-decoration: none;
                    display: inline-block;
                }
                .zenux-oauth-button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
                }
                .zenux-oauth-debug {
                    background: rgba(0, 0, 0, 0.3);
                    padding: 15px;
                    border-radius: 10px;
                    margin-top: 20px;
                    text-align: left;
                    font-family: 'Courier New', monospace;
                    font-size: 11px;
                    max-height: 300px;
                    overflow-y: auto;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
            </style>
            <div class="zenux-oauth-callback">
                <div class="zenux-oauth-container">
                    <div id="zenux-oauth-loading">
                        <div class="zenux-oauth-spinner"></div>
                        <h1>Processing Authentication</h1>
                        <p>Please wait while we complete your login...</p>
                    </div>
                    
                    <div id="zenux-oauth-success" class="zenux-oauth-hidden">
                        <div style="font-size: 3rem; margin-bottom: 15px;">✓</div>
                        <h1 class="zenux-oauth-success">Authentication Successful</h1>
                        <p id="zenux-oauth-success-message"></p>
                    </div>
                    
                    <div id="zenux-oauth-error" class="zenux-oauth-hidden">
                        <div style="font-size: 3rem; margin-bottom: 15px;">✗</div>
                        <h1 class="zenux-oauth-error">Authentication Failed</h1>
                        <p id="zenux-oauth-error-message"></p>
                        <div>
                            <button class="zenux-oauth-button" onclick="window.zenuxOAuthCallback?.retry()">Try Again</button>
                            <button class="zenux-oauth-button" onclick="window.zenuxOAuthCallback?.closeWindow()">Close</button>
                        </div>
                    </div>
                    
                    <div id="zenux-oauth-debug" class="zenux-oauth-debug zenux-oauth-hidden"></div>
                </div>
            </div>
        `;
    }

    async handleCallback() {
        try {
            this.debugLog('Starting callback processing');

            const urlParams = new URLSearchParams(window.location.search);
            const code = urlParams.get('code');
            const state = urlParams.get('state');
            const error = urlParams.get('error');
            const errorDescription = urlParams.get('error_description');

            this.debugLog('URL parameters', { 
                hasCode: !!code, 
                hasState: !!state, 
                error, 
                errorDescription 
            });

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

            if (window.ZenuxOAuthInstance) {
                this.debugLog('Using main ZenuxOAuth instance');
                const tokens = await window.ZenuxOAuthInstance.handleCallback();
                this.showSuccess('Authentication complete!');
                this.notifyParent('success', { tokens });
                return tokens;
            }

            const tokens = await this.exchangeCodeManually(code, state);
            this.showSuccess('Authentication complete!');
            this.notifyParent('success', { tokens });
            return tokens;

        } catch (error) {
            this.debugLog('Callback processing failed', error);
            this.showError(error.message);
            this.notifyParent('error', { 
                error: error.message, 
                code: error.code || 'CALLBACK_ERROR' 
            });
            throw error;
        }
    }

    async exchangeCodeManually(code, state) {
        this.debugLog('Manual token exchange started');

        const config = this.getOAuthConfig();
        const codeVerifier = this.getStoredValue('code_verifier');
        const storedState = this.getStoredValue('state');

        this.debugLog('Retrieved configuration', {
            hasCodeVerifier: !!codeVerifier,
            hasStoredState: !!storedState,
            clientId: config.clientId,
            authServer: config.authServer
        });

        if (storedState && state !== storedState) {
            throw new ZenuxOAuthError('State parameter mismatch', 'STATE_MISMATCH');
        }

        if (!codeVerifier) {
            throw new ZenuxOAuthError('No code verifier found', 'NO_CODE_VERIFIER');
        }

        const tokenData = new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: config.redirectUri,
            client_id: config.clientId,
            code_verifier: codeVerifier
        });

        const response = await fetch(`${config.authServer}${config.tokenEndpoint}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            },
            body: tokenData
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new ZenuxOAuthError(
                `Token exchange failed: ${response.status}`,
                'TOKEN_EXCHANGE_FAILED',
                { status: response.status, response: errorText }
            );
        }

        const tokens = await response.json();
        
        this.setStoredValue('tokens', JSON.stringify(tokens));
        this.clearStoredValue('code_verifier');
        this.clearStoredValue('state');
        this.clearStoredValue('nonce');

        this.debugLog('Manual token exchange successful');
        return tokens;
    }

    getOAuthConfig() {
        const urlParams = new URLSearchParams(window.location.search);
        
        return {
            clientId: urlParams.get('client_id') || this.getStoredValue('client_id'),
            authServer: urlParams.get('auth_server') || this.getStoredValue('auth_server') || 'https://api.auth.zenuxs.in',
            redirectUri: window.location.origin + window.location.pathname,
            tokenEndpoint: '/oauth/token',
            authorizeEndpoint: '/oauth/authorize'
        };
    }

    getStoredValue(key) {
        const locations = [
            () => sessionStorage.getItem(this.config.storagePrefix + key),
            () => localStorage.getItem(this.config.storagePrefix + key),
            () => sessionStorage.getItem(key),
            () => localStorage.getItem(key)
        ];

        for (const getter of locations) {
            try {
                const value = getter();
                if (value) {
                    this.debugLog(`Found ${key} in storage`);
                    return value;
                }
            } catch (e) {
                continue;
            }
        }
        return null;
    }

    setStoredValue(key, value) {
        try {
            sessionStorage.setItem(this.config.storagePrefix + key, value);
        } catch (e) {
            this.debugLog('Failed to store value', e);
        }
    }

    clearStoredValue(key) {
        try {
            sessionStorage.removeItem(this.config.storagePrefix + key);
            localStorage.removeItem(this.config.storagePrefix + key);
            sessionStorage.removeItem(key);
            localStorage.removeItem(key);
        } catch (e) {
            this.debugLog('Storage cleanup error', e);
        }
    }

    notifyParent(type, data) {
        if (!window.opener || window.opener.closed) {
            this.debugLog('No parent window to notify');
            return false;
        }

        this.debugLog(`Notifying parent: ${type}`, data);
        
        window.opener.postMessage({
            type: `zenux_oauth_${type}`,
            ...data,
            timestamp: Date.now()
        }, '*');

        return true;
    }

    showSuccess(message = null) {
        this.showSection('success');
        if (this.elements.successMessage) {
            this.elements.successMessage.textContent = message || this.config.successMessage;
        }

        if (this.config.autoClose) {
            setTimeout(() => {
                if (window.opener && !window.opener.closed) {
                    window.close();
                }
            }, this.config.autoCloseDelay);
        }
    }

    showError(message = null) {
        this.showSection('error');
        if (this.elements.errorMessage) {
            this.elements.errorMessage.textContent = message || this.config.errorMessage;
        }
    }

    showSection(sectionName) {
        if (this.elements.loading) this.elements.loading.classList.add('zenux-oauth-hidden');
        if (this.elements.success) this.elements.success.classList.add('zenux-oauth-hidden');
        if (this.elements.error) this.elements.error.classList.add('zenux-oauth-hidden');

        const section = this.elements[sectionName];
        if (section) section.classList.remove('zenux-oauth-hidden');

        if (this.config.debug && this.elements.debug) {
            this.elements.debug.classList.remove('zenux-oauth-hidden');
        }
    }

    retry() {
        this.clearStoredValue('code_verifier');
        this.clearStoredValue('state');
        window.location.href = this.config.homeUrl;
    }

    closeWindow() {
        if (window.opener && !window.opener.closed) {
            window.close();
        } else {
            window.location.href = this.config.homeUrl;
        }
    }

    debugLog(message, data = null) {
        if (!this.config.debug) return;
        
        const timestamp = new Date().toLocaleTimeString();
        let logMessage = `[${timestamp}] ${message}`;
        
        if (data) {
            logMessage += '\n' + JSON.stringify(data, null, 2);
        }
        
        if (this.elements.debug) {
            this.elements.debug.textContent += logMessage + '\n\n';
        }
        
        console.log('[ZenuxOAuth Callback]', message, data);
    }
}

// ==================== STATIC METHODS ====================

ZenuxOAuth.create = function(config) {
    return new ZenuxOAuth(config);
};

ZenuxOAuth.createCallbackHandler = function(config) {
    if (!Environment.isBrowser) {
        console.warn('Callback handler is only available in browser environments');
        return null;
    }
    return new ZenuxOAuthCallbackHandler(config);
};

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

ZenuxOAuth.Error = ZenuxOAuthError; 
ZenuxOAuth.VERSION = '2.3.0';
ZenuxOAuth.Environment = Environment;

// ==================== AUTO-INITIALIZATION ====================

if (Environment.isBrowser) {
    const isCallbackPage = window.location.pathname.includes('callback') || 
                          window.location.search.includes('code=') ||
                          window.location.search.includes('error=');
    
    if (isCallbackPage) {
        window.zenuxOAuthCallback = new ZenuxOAuthCallbackHandler();
    }
}

// ==================== UMD EXPORT ====================

(function (global, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module !== 'undefined' && module.exports) {
        const result = factory();
        module.exports = result;
        module.exports.ZenuxOAuthCallbackHandler = ZenuxOAuthCallbackHandler;
        module.exports.ZenuxOAuthError = ZenuxOAuthError;
    } else {
        const result = factory();
        global.ZenuxOAuth = result;
        global.ZenuxOAuthCallbackHandler = ZenuxOAuthCallbackHandler;
        global.ZenuxOAuthError = ZenuxOAuthError;
    }
}(typeof window !== 'undefined' ? window : this, function () {
    return ZenuxOAuth;
}));