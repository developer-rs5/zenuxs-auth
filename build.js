const fs = require('fs');
const path = require('path');
const uglifyJS = require('uglify-js');

// Create dist directory if it doesn't exist
const distDir = path.join(__dirname, 'dist');
if (!fs.existsSync(distDir)) {
    fs.mkdirSync(distDir, { recursive: true });
}

// Read source file
const sourcePath = path.join(__dirname, 'src', 'zenux-oauth.js');
let sourceCode = fs.readFileSync(sourcePath, 'utf8');

// Create regular version (UMD)
fs.writeFileSync(
    path.join(distDir, 'zenux-oauth.js'),
    sourceCode
);

// Create minified version (UMD)
const minified = uglifyJS.minify(sourceCode);
if (minified.error) {
    console.error('Minification error:', minified.error);
    process.exit(1);
}

fs.writeFileSync(
    path.join(distDir, 'zenux-oauth.min.js'),
    minified.code
);

// Create ES module version (without UMD wrapper)
let esmCode = sourceCode
    // Remove UMD wrapper
    .replace(/\/\/ UMD pattern for universal module definition[\s\S]*?\(typeof window !== 'undefined' \? window : this, function \(\) \{[\s\S]*?return ZenuxOAuth;[\s\S]*?\}\)\);/, '')
    // Add ES module export
    .trim() + '\n\nexport default ZenuxOAuth;';

fs.writeFileSync(
    path.join(distDir, 'zenux-oauth.esm.js'),
    esmCode
);

// Create CommonJS version
const cjsCode = sourceCode
    // Remove UMD wrapper
    .replace(/\/\/ UMD pattern for universal module definition[\s\S]*?\(typeof window !== 'undefined' \? window : this, function \(\) \{[\s\S]*?return ZenuxOAuth;[\s\S]*?\}\)\);/, '')
    // Add CommonJS export
    .trim() + '\n\nmodule.exports = ZenuxOAuth;';

fs.writeFileSync(
    path.join(distDir, 'zenux-oauth.cjs.js'),
    cjsCode
);

// Create TypeScript definitions
const typeDefinitions = `declare interface ZenuxOAuthConfig {
    clientId: string;
    redirectUri?: string;
    authServer?: string;
    frontend?: string;
    scopes?: string;
    storage?: 'localStorage' | 'sessionStorage';
    autoRefresh?: boolean;
}

declare interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
}

declare interface UserInfo {
    sub: string;
    name?: string;
    email?: string;
    email_verified?: boolean;
    picture?: string;
    given_name?: string;
    family_name?: string;
}

declare class ZenuxOAuth {
    constructor(config: ZenuxOAuthConfig);
    
    login(options?: { popup?: boolean; redirectUri?: string; scopes?: string }): Promise<void | TokenResponse>;
    handleCallback(): Promise<TokenResponse>;
    getUserInfo(): Promise<UserInfo>;
    getTokens(): TokenResponse | null;
    isAuthenticated(): boolean;
    logout(): void;
    refreshTokens(): Promise<TokenResponse>;
    decodeJWT(token: string): any;
    getAuthorizationUrl(options?: any): Promise<string>;
}

export default ZenuxOAuth;
export { ZenuxOAuth, ZenuxOAuthConfig, TokenResponse, UserInfo };`;

fs.writeFileSync(
    path.join(distDir, 'zenux-oauth.d.ts'),
    typeDefinitions
);

// Copy callback.html to dist
fs.copyFileSync(
    path.join(__dirname, 'callback.html'),
    path.join(distDir, 'callback.html')
);

console.log('Build completed successfully!');
console.log('✓ Created dist/zenux-oauth.js (UMD)');
console.log('✓ Created dist/zenux-oauth.min.js (UMD minified)');
console.log('✓ Created dist/zenux-oauth.esm.js (ES Module)');
console.log('✓ Created dist/zenux-oauth.cjs.js (CommonJS)');
console.log('✓ Created dist/zenux-oauth.d.ts (TypeScript)');
console.log('✓ Copied callback.html to dist/');