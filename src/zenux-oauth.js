/**
 * ZenuxOAuth - Universal OAuth 2.0 PKCE Client Library
 * @version 2.2.0
 * @license MIT
 * @description Works in both Browser and Node.js environments
 */

// ==================== ENVIRONMENT DETECTION ====================

const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';
const isNode = typeof process !== 'undefined' && process.versions && process.versions.node;

// ==================== POLYFILLS FOR NODE.JS ====================

let nodeCrypto, nodeFetch;
if (isNode) {
    try {
        nodeCrypto = require('crypto');
    } catch (e) {
        console.warn('Crypto module not available');
    }
    try {
        nodeFetch = require('node-fetch');
    } catch (e) {
        // node-fetch not available, will use global fetch if available
    }
}

// ==================== ERROR CLASS ====================

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

// ==================== MAIN CLASS ====================

class ZenuxOAuth {
    constructor(config = {}) {
        this.validateConfig(config);

        this.config = {
            authServer: config.authServer || 'https://api.auth.zenuxs.in',
            clientId: config.clientId,
            redirectUri: config.redirectUri || this.getDefaultRedirectUri(),
            scopes: config.scopes || 'openid profile email',
            authorizeEndpoint: config.authorizeEndpoint || '/oauth/authorize',
            tokenEndpoint: config.tokenEndpoint || '/oauth/token',
            userinfoEndpoint: config.userinfoEndpoint || '/oauth/userinfo',
            revokeEndpoint: config.revokeEndpoint || '/oauth/revoke',
            storage: config.storage || 'sessionStorage',
            storagePrefix: config.storagePrefix || 'zenux_oauth_',
            usePKCE: config.usePKCE !== false, // PKCE is enabled by default
            useCSRF: config.useCSRF !== false,
            validateState: config.validateState !== false,
            autoRefresh: config.autoRefresh !== false,
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
            fetchFunction: config.fetchFunction || this.getDefaultFetch(),
            storageAdapter: config.storageAdapter || null,
            enableCallbackHandler: config.enableCallbackHandler !== false
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
        this._storageCache = {};

        this.init();

        if (isBrowser) {
            window.ZenuxOAuthInstance = this;
            // Show version in browser console
            console.log(`ZenuxOAuth v${ZenuxOAuth.VERSION} - Universal OAuth 2.0 PKCE Client`);
        }
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

        if (isBrowser && config.storage && !['localStorage', 'sessionStorage'].includes(config.storage)) {
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
        if (isBrowser && window.location) {
            return `${window.location.origin}/callback`;
        }
        return 'http://localhost:3000/callback';
    }

    getDefaultFetch() {
        if (isBrowser && typeof fetch !== 'undefined') {
            return fetch.bind(window);
        }
        if (isNode && nodeFetch) {
            return nodeFetch;
        }
        if (isNode && typeof fetch !== 'undefined') {
            return fetch;
        }
        // Fallback for Node.js without fetch
        if (isNode) {
            return async (url, options) => {
                const https = require('https');
                const { URL } = require('url');
                
                return new Promise((resolve, reject) => {
                    const urlObj = new URL(url);
                    const postData = options?.body ? options.body.toString() : null;
                    
                    const reqOptions = {
                        hostname: urlObj.hostname,
                        port: urlObj.port,
                        path: urlObj.pathname + urlObj.search,
                        method: options?.method || 'GET',
                        headers: options?.headers || {}
                    };
                    
                    const req = https.request(reqOptions, (res) => {
                        let data = '';
                        
                        res.on('data', (chunk) => {
                            data += chunk;
                        });
                        
                        res.on('end', () => {
                            resolve({
                                ok: res.statusCode >= 200 && res.statusCode < 300,
                                status: res.statusCode,
                                statusText: res.statusMessage,
                                json: () => Promise.resolve(JSON.parse(data)),
                                text: () => Promise.resolve(data)
                            });
                        });
                    });
                    
                    req.on('error', (error) => {
                        reject(error);
                    });
                    
                    if (postData) {
                        req.write(postData);
                    }
                    
                    req.end();
                });
            };
        }
        return null;
    }

    init() {
        this.debugLog('Initializing ZenuxOAuth', { 
            environment: isBrowser ? 'browser' : 'node',
            config: { ...this.config, clientId: '[HIDDEN]' } // Don't log clientId
        });
        
        this.loadTokens();

        if (this.config.autoRefresh && isBrowser) {
            this.setupAutoRefresh();
        }

        if (isBrowser) {
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden && this.isAuthenticated()) {
                    this.checkAndRefreshToken();
                }
            });
        }
    }

    async generateRandomString(length = 128) {
        const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
        
        if (isBrowser && crypto && crypto.getRandomValues) {
            const randomValues = new Uint8Array(length);
            crypto.getRandomValues(randomValues);
            return Array.from(randomValues, byte => charset[byte % charset.length]).join('');
        } else if (isNode && nodeCrypto) {
            return nodeCrypto.randomBytes(length)
                .reduce((str, byte) => str + charset[byte % charset.length], '');
        } else {
            // Fallback for environments without crypto
            let result = '';
            for (let i = 0; i < length; i++) {
                result += charset[Math.floor(Math.random() * charset.length)];
            }
            return result;
        }
    }

    async sha256(plain) {
        if (isNode && nodeCrypto) {
            const hash = nodeCrypto.createHash('sha256').update(plain).digest('base64');
            return hash.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        if (isBrowser && crypto && crypto.subtle) {
            const encoder = new TextEncoder();
            const data = encoder.encode(plain);
            const hash = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hash));
            const hashBase64 = btoa(String.fromCharCode(...hashArray));
            return hashBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        }

        throw new ZenuxOAuthError(
            'SHA-256 not supported in this environment',
            'CRYPTO_NOT_SUPPORTED'
        );
    }

    async login(options = {}) {
        try {
            if (this.config.onBeforeLogin) {
                await this.config.onBeforeLogin();
            }

            this.debugLog('Starting OAuth flow', options);

            // Generate PKCE code verifier and challenge
            if (this.config.usePKCE) {
                this.session.codeVerifier = await this.generateRandomString(128);
                this.session.codeChallenge = await this.sha256(this.session.codeVerifier);
                this.setStorage('code_verifier', this.session.codeVerifier);
            }

            // Generate state and nonce
            this.session.state = await this.generateRandomString(32);
            this.setStorage('state', this.session.state);

            this.session.nonce = await this.generateRandomString(32);
            this.setStorage('nonce', this.session.nonce);

            if (this.config.useCSRF) {
                this.session.csrfToken = await this.generateRandomString(32);
                this.setStorage('csrf_token', this.session.csrfToken);
            }

            const authParams = {
                client_id: this.config.clientId,
                redirect_uri: options.redirectUri || this.config.redirectUri,
                scope: options.scopes || this.config.scopes,
                response_type: 'code',
                state: this.session.state,
                nonce: this.session.nonce,
                ...this.config.extraAuthParams,
                ...(options.extraParams || {})
            };

            if (this.config.usePKCE) {
                authParams.code_challenge = this.session.codeChallenge;
                authParams.code_challenge_method = 'S256';
            }

            const params = new URLSearchParams(authParams);
            const authUrl = `${this.config.authServer}${this.config.authorizeEndpoint}?${params.toString()}`;

            this.debugLog('Authorization URL built', { 
                authUrl: `${this.config.authServer}${this.config.authorizeEndpoint}`,
                hasCodeChallenge: !!this.session.codeChallenge 
            });

            if (isBrowser) {
                if (options.popup) {
                    return this.loginWithPopup(authUrl, options);
                } else if (options.silent) {
                    return this.loginSilent(authUrl, options);
                } else {
                    window.location.href = authUrl;
                    return null;
                }
            } else {
                return {
                    authUrl,
                    state: this.session.state,
                    codeVerifier: this.session.codeVerifier,
                    nonce: this.session.nonce
                };
            }
        } catch (error) {
            this.debugLog('Login error', error);
            this.emit('error', error);
            throw error;
        }
    }

    loginWithPopup(authUrl, options = {}) {
        if (!isBrowser) {
            return Promise.reject(new ZenuxOAuthError(
                'Popup login only available in browser',
                'POPUP_NOT_AVAILABLE'
            ));
        }

        return new Promise((resolve, reject) => {
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

    async handleCallback(callbackUrl = null) {
        try {
            this.debugLog('Handling OAuth callback');

            const url = callbackUrl || (isBrowser ? window.location.href : null);

            if (!url) {
                throw new ZenuxOAuthError('No callback URL provided', 'NO_CALLBACK_URL');
            }

            const urlObj = new URL(url);
            const params = new URLSearchParams(urlObj.search);

            const code = params.get('code');
            const state = params.get('state');
            const error = params.get('error');
            const errorDescription = params.get('error_description');

            this.debugLog('Callback parameters', { 
                hasCode: !!code, 
                hasState: !!state, 
                error 
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

            if (this.config.validateState) {
                const storedState = this.getStorage('state');
                if (state !== storedState) {
                    throw new ZenuxOAuthError('State parameter mismatch', 'STATE_MISMATCH', {
                        received: state,
                        expected: storedState
                    });
                }
            }

            const codeVerifier = this.getStorage('code_verifier');
            if (this.config.usePKCE && !codeVerifier) {
                throw new ZenuxOAuthError('No code verifier found', 'NO_CODE_VERIFIER');
            }

            const tokens = await this.exchangeCodeForTokens(code, codeVerifier);

            this.session.tokens = tokens;
            this.setStorage('tokens', JSON.stringify(tokens));

            // Clean up temporary storage
            this.clearStorage('code_verifier');
            this.clearStorage('state');
            this.clearStorage('nonce');
            this.clearStorage('csrf_token');

            if (isBrowser && history && history.replaceState) {
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
            throw new ZenuxOAuthError(
                'No fetch function available. Please provide fetchFunction in config.',
                'NO_FETCH_FUNCTION'
            );
        }

        const tokenData = {
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: this.config.redirectUri,
            client_id: this.config.clientId,
            ...this.config.extraTokenParams
        };

        if (this.config.usePKCE && codeVerifier) {
            tokenData.code_verifier = codeVerifier;
        }

        const response = await this.config.fetchFunction(
            `${this.config.authServer}${this.config.tokenEndpoint}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams(tokenData)
            }
        );

        if (!response.ok) {
            let errorDetails;
            try {
                errorDetails = await response.json();
            } catch {
                errorDetails = await response.text();
            }

            throw new ZenuxOAuthError(
                `Token exchange failed: ${response.status} ${response.statusText}`,
                'TOKEN_EXCHANGE_FAILED',
                { 
                    status: response.status,
                    statusText: response.statusText,
                    response: errorDetails 
                }
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
        return this.getTokens();
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

            if (!this.config.fetchFunction) {
                throw new ZenuxOAuthError('No fetch function available', 'NO_FETCH_FUNCTION');
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
                    `Token refresh failed: ${response.status}`,
                    'TOKEN_REFRESH_FAILED',
                    { status: response.status }
                );
            }

            const newTokens = await response.json();

            if (newTokens.expires_in) {
                newTokens.expires_at = Date.now() + (newTokens.expires_in * 1000);
            }

            if (!newTokens.refresh_token) {
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

    async getUserInfo() {
        try {
            const tokens = this.getTokens();
            if (!tokens?.access_token) {
                throw new ZenuxOAuthError('No access token available', 'NO_ACCESS_TOKEN');
            }

            if (!this.config.fetchFunction) {
                throw new ZenuxOAuthError('No fetch function available', 'NO_FETCH_FUNCTION');
            }

            const response = await this.config.fetchFunction(
                `${this.config.authServer}${this.config.userinfoEndpoint}`,
                {
                    headers: {
                        'Authorization': `Bearer ${tokens.access_token}`,
                        'Accept': 'application/json'
                    }
                }
            );

            if (!response.ok) {
                throw new ZenuxOAuthError(
                    `UserInfo request failed: ${response.status}`,
                    'USERINFO_FAILED'
                );
            }

            return await response.json();
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

    // ==================== STORAGE METHODS ====================

    getStorage(key) {
        const fullKey = this.config.storagePrefix + key;

        if (this.config.storageAdapter && typeof this.config.storageAdapter.get === 'function') {
            return this.config.storageAdapter.get(fullKey);
        }

        if (!isBrowser) {
            return this._storageCache[fullKey] || null;
        }

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

        if (this.config.storageAdapter && typeof this.config.storageAdapter.set === 'function') {
            this.config.storageAdapter.set(fullKey, value);
            return;
        }

        if (!isBrowser) {
            this._storageCache[fullKey] = value;
            return;
        }

        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.setItem(fullKey, value);
        } catch (e) {
            this.debugLog('Storage set failed', e);
        }
    }

    clearStorage(key) {
        const fullKey = this.config.storagePrefix + key;

        if (this.config.storageAdapter && typeof this.config.storageAdapter.remove === 'function') {
            this.config.storageAdapter.remove(fullKey);
            return;
        }

        if (!isBrowser) {
            delete this._storageCache[fullKey];
            return;
        }

        try {
            const storage = this.config.storage === 'localStorage' ? localStorage : sessionStorage;
            storage.removeItem(fullKey);
        } catch (e) {
            this.debugLog('Storage clear failed', e);
        }
    }

    // ==================== EVENT METHODS ====================

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

    debugLog(message, data = null) {
        if (!this.config.debug) return;

        const timestamp = new Date().toISOString();
        console.log(`[ZenuxOAuth ${timestamp}]`, message, data || '');
    }

    // ==================== UTILITY METHODS ====================

    async getAuthorizationUrl(options = {}) {
        if (this.config.usePKCE) {
            this.session.codeVerifier = await this.generateRandomString(128);
            this.session.codeChallenge = await this.sha256(this.session.codeVerifier);
        }

        this.session.state = await this.generateRandomString(32);
        this.session.nonce = await this.generateRandomString(32);

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

// ==================== STATIC METHODS ====================

ZenuxOAuth.create = function(config) {
    return new ZenuxOAuth(config);
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
ZenuxOAuth.VERSION = '2.2.0';
ZenuxOAuth.isBrowser = isBrowser;
ZenuxOAuth.isNode = isNode;
