import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import express, { type Express, type Response } from 'express';
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidRequestError,
  InvalidScopeError,
  InvalidTokenError,
  InvalidTargetError,
  OAuthError,
  ServerError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { resourceUrlFromServerUrl } from '@modelcontextprotocol/sdk/shared/auth-utils.js';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from '@modelcontextprotocol/sdk/shared/auth.js';
import { z } from 'zod';

const SUPPORTED_SCOPES = ['mcp:tools', 'offline_access'] as const;

type SupportedScopeDto = (typeof SUPPORTED_SCOPES)[number];

export type OAuthConfigDto = {
  issuerUrl: URL;
  resourceServerUrl: URL;
  username: string;
  password: string;
  resourceName: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  storagePath: string;
};

type AuthorizationCodeDto = {
  code: string;
  clientId: string;
  redirectUri: string;
  codeChallenge?: string;
  scopes: SupportedScopeDto[];
  resource: URL;
  expiresAt: number;
};

type AccessTokenDto = {
  token: string;
  clientId: string;
  scopes: SupportedScopeDto[];
  resource: URL;
  expiresAt: number;
};

type RefreshTokenDto = {
  token: string;
  clientId: string;
  scopes: SupportedScopeDto[];
  resource: URL;
  expiresAt: number;
};

type LoginFormDto = {
  client_id: string;
  redirect_uri?: string;
  response_type: 'code';
  code_challenge?: string;
  code_challenge_method?: 'S256';
  scope?: string;
  state?: string;
  resource?: string;
  username?: string;
  password?: string;
};

const loginFormSchema = z.object({
  client_id: z.string(),
  redirect_uri: z.string().url().optional(),
  response_type: z.literal('code'),
  code_challenge: z.string().optional(),
  code_challenge_method: z.literal('S256').optional(),
  scope: z.string().optional(),
  state: z.string().optional(),
  resource: z.string().url().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
});

type PersistedAuthorizationCodeDto = Omit<AuthorizationCodeDto, 'resource'> & {
  resource: string;
};

type PersistedAccessTokenDto = Omit<AccessTokenDto, 'resource'> & {
  resource: string;
};

type PersistedRefreshTokenDto = Omit<RefreshTokenDto, 'resource'> & {
  resource: string;
};

type PersistedOAuthStoreDto = {
  clients: Record<string, OAuthClientInformationFull>;
  authorizationCodes: Record<string, PersistedAuthorizationCodeDto>;
  accessTokens: Record<string, PersistedAccessTokenDto>;
  refreshTokens: Record<string, PersistedRefreshTokenDto>;
};

const emptyOAuthStore = (): PersistedOAuthStoreDto => ({
  clients: {},
  authorizationCodes: {},
  accessTokens: {},
  refreshTokens: {},
});

class FileBackedOAuthStore {
  constructor(private readonly storagePath: string) {
    this.ensureStoreFile();
  }

  getClient(clientId: string): OAuthClientInformationFull | undefined {
    return this.readStore().clients[clientId];
  }

  setClient(client: OAuthClientInformationFull): void {
    const store = this.readStore();

    store.clients[client.client_id] = client;
    this.writeStore(store);
  }

  getAuthorizationCode(code: string): AuthorizationCodeDto | undefined {
    const store = this.readStore();
    const authorizationCode = store.authorizationCodes[code];

    if (!authorizationCode) {
      return undefined;
    }

    if (authorizationCode.expiresAt <= Date.now()) {
      delete store.authorizationCodes[code];
      this.writeStore(store);
      return undefined;
    }

    return {
      ...authorizationCode,
      resource: new URL(authorizationCode.resource),
    };
  }

  setAuthorizationCode(code: AuthorizationCodeDto): void {
    const store = this.readStore();

    store.authorizationCodes[code.code] = {
      ...code,
      resource: code.resource.href,
    };
    this.writeStore(store);
  }

  deleteAuthorizationCode(code: string): void {
    const store = this.readStore();

    delete store.authorizationCodes[code];
    this.writeStore(store);
  }

  getAccessToken(token: string): AccessTokenDto | undefined {
    const store = this.readStore();
    const accessToken = store.accessTokens[token];

    if (!accessToken) {
      return undefined;
    }

    if (accessToken.expiresAt <= Date.now()) {
      delete store.accessTokens[token];
      this.writeStore(store);
      return undefined;
    }

    return {
      ...accessToken,
      resource: new URL(accessToken.resource),
    };
  }

  setAccessToken(token: AccessTokenDto): void {
    const store = this.readStore();

    store.accessTokens[token.token] = {
      ...token,
      resource: token.resource.href,
    };
    this.writeStore(store);
  }

  deleteAccessToken(token: string): void {
    const store = this.readStore();

    delete store.accessTokens[token];
    this.writeStore(store);
  }

  getRefreshToken(token: string): RefreshTokenDto | undefined {
    const store = this.readStore();
    const refreshToken = store.refreshTokens[token];

    if (!refreshToken) {
      return undefined;
    }

    if (refreshToken.expiresAt <= Date.now()) {
      delete store.refreshTokens[token];
      this.writeStore(store);
      return undefined;
    }

    return {
      ...refreshToken,
      resource: new URL(refreshToken.resource),
    };
  }

  setRefreshToken(token: RefreshTokenDto): void {
    const store = this.readStore();

    store.refreshTokens[token.token] = {
      ...token,
      resource: token.resource.href,
    };
    this.writeStore(store);
  }

  deleteRefreshToken(token: string): void {
    const store = this.readStore();

    delete store.refreshTokens[token];
    this.writeStore(store);
  }

  private ensureStoreFile(): void {
    mkdirSync(dirname(this.storagePath), { recursive: true });

    try {
      this.readStore();
    } catch {
      this.writeStore(emptyOAuthStore());
    }
  }

  private readStore(): PersistedOAuthStoreDto {
    const raw = readFileSync(this.storagePath, 'utf8');
    const parsed = JSON.parse(raw) as Partial<PersistedOAuthStoreDto>;
    const now = Date.now();
    const store: PersistedOAuthStoreDto = {
      ...emptyOAuthStore(),
      ...parsed,
      clients: parsed.clients ?? {},
      authorizationCodes: parsed.authorizationCodes ?? {},
      accessTokens: parsed.accessTokens ?? {},
      refreshTokens: parsed.refreshTokens ?? {},
    };
    let changed = false;

    for (const [key, value] of Object.entries(store.authorizationCodes)) {
      if (value.expiresAt <= now) {
        delete store.authorizationCodes[key];
        changed = true;
      }
    }

    for (const [key, value] of Object.entries(store.accessTokens)) {
      if (value.expiresAt <= now) {
        delete store.accessTokens[key];
        changed = true;
      }
    }

    for (const [key, value] of Object.entries(store.refreshTokens)) {
      if (value.expiresAt <= now) {
        delete store.refreshTokens[key];
        changed = true;
      }
    }

    if (changed) {
      this.writeStore(store);
    }

    return store;
  }

  private writeStore(store: PersistedOAuthStoreDto): void {
    mkdirSync(dirname(this.storagePath), { recursive: true });
    const tempPath = `${this.storagePath}.tmp`;

    writeFileSync(tempPath, JSON.stringify(store, null, 2), 'utf8');
    renameSync(tempPath, this.storagePath);
  }
}

class PersistentClientsStore {
  constructor(private readonly store: FileBackedOAuthStore) {}

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    return this.store.getClient(clientId);
  }

  async registerClient(client: OAuthClientInformationFull): Promise<OAuthClientInformationFull> {
    this.store.setClient(client);
    return client;
  }
}

class LocalOAuthProvider implements OAuthServerProvider {
  readonly clientsStore: PersistentClientsStore;
  private readonly allowedScopes = new Set<SupportedScopeDto>(SUPPORTED_SCOPES);
  private readonly store: FileBackedOAuthStore;

  constructor(private readonly config: OAuthConfigDto) {
    this.store = new FileBackedOAuthStore(config.storagePath);
    this.clientsStore = new PersistentClientsStore(this.store);
  }

  async authorize(_client: OAuthClientInformationFull, _params: AuthorizationParams, _res: Response): Promise<void> {
    throw new ServerError('Authorization must be handled by the interactive login route');
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    const code = this.store.getAuthorizationCode(authorizationCode);

    if (!code || code.clientId !== client.client_id || code.expiresAt < Date.now()) {
      throw new InvalidGrantError('Invalid authorization code');
    }

    if (!code.codeChallenge) {
      throw new InvalidGrantError('Authorization code does not use PKCE');
    }

    return code.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const code = this.store.getAuthorizationCode(authorizationCode);

    if (!code) {
      throw new InvalidGrantError('Invalid authorization code');
    }

    if (code.expiresAt < Date.now()) {
      this.store.deleteAuthorizationCode(authorizationCode);
      throw new InvalidGrantError('Authorization code expired');
    }

    if (code.clientId !== client.client_id) {
      throw new InvalidGrantError('Authorization code was not issued to this client');
    }

    if (redirectUri && redirectUri !== code.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the original authorization request');
    }

    if (resource && resource.href !== code.resource.href) {
      throw new InvalidTargetError('Invalid resource');
    }

    if (code.codeChallenge) {
      if (!_codeVerifier) {
        throw new InvalidGrantError('Missing code_verifier');
      }

      const verifierHash = createCodeChallenge(_codeVerifier);

      if (verifierHash !== code.codeChallenge) {
        throw new InvalidGrantError('code_verifier does not match the challenge');
      }
    }

    this.store.deleteAuthorizationCode(authorizationCode);

    return this.issueTokens({
      clientId: client.client_id,
      scopes: code.scopes,
      resource: code.resource,
      issueRefreshToken: code.scopes.includes('offline_access'),
    });
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const storedRefreshToken = this.store.getRefreshToken(refreshToken);

    if (!storedRefreshToken) {
      throw new InvalidGrantError('Invalid refresh token');
    }

    if (storedRefreshToken.expiresAt < Date.now()) {
      this.store.deleteRefreshToken(refreshToken);
      throw new InvalidGrantError('Refresh token expired');
    }

    if (storedRefreshToken.clientId !== client.client_id) {
      throw new InvalidGrantError('Refresh token was not issued to this client');
    }

    if (resource && resource.href !== storedRefreshToken.resource.href) {
      throw new InvalidTargetError('Invalid resource');
    }

    const requestedScopes = scopes ? this.parseScopes(scopes.join(' '), storedRefreshToken.scopes) : storedRefreshToken.scopes;

    return this.issueTokens({
      clientId: client.client_id,
      scopes: requestedScopes,
      resource: resource ?? storedRefreshToken.resource,
      issueRefreshToken: requestedScopes.includes('offline_access'),
    });
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const accessToken = this.store.getAccessToken(token);

    if (!accessToken || accessToken.expiresAt < Date.now()) {
      throw new InvalidTokenError('Invalid or expired access token');
    }

    return {
      token: accessToken.token,
      clientId: accessToken.clientId,
      scopes: accessToken.scopes,
      expiresAt: Math.floor(accessToken.expiresAt / 1000),
      resource: accessToken.resource,
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const accessToken = this.store.getAccessToken(request.token);

    if (accessToken && accessToken.clientId === client.client_id) {
      this.store.deleteAccessToken(request.token);
    }

    const refreshToken = this.store.getRefreshToken(request.token);

    if (refreshToken && refreshToken.clientId === client.client_id) {
      this.store.deleteRefreshToken(request.token);
    }
  }

  async getClient(clientId: string): Promise<OAuthClientInformationFull> {
    const client = await this.clientsStore.getClient(clientId);

    if (!client) {
      throw new InvalidClientError('Invalid client_id');
    }

    return client;
  }

  resolveRedirectUri(client: OAuthClientInformationFull, redirectUri?: string): string {
    if (redirectUri) {
      if (!client.redirect_uris.includes(redirectUri)) {
        throw new InvalidRequestError('Unregistered redirect_uri');
      }

      return redirectUri;
    }

    if (client.redirect_uris.length !== 1) {
      throw new InvalidRequestError('redirect_uri must be specified when client has multiple registered URIs');
    }

    return client.redirect_uris[0];
  }

  validateCredentials(username?: string, password?: string): boolean {
    if (!username || !password) {
      return false;
    }

    const expectedUsername = Buffer.from(this.config.username);
    const actualUsername = Buffer.from(username);
    const expectedPassword = Buffer.from(this.config.password);
    const actualPassword = Buffer.from(password);

    if (expectedUsername.length !== actualUsername.length || expectedPassword.length !== actualPassword.length) {
      return false;
    }

    return timingSafeEqual(expectedUsername, actualUsername) && timingSafeEqual(expectedPassword, actualPassword);
  }

  createAuthorizationCode(input: {
    client: OAuthClientInformationFull;
    redirectUri: string;
    scope?: string;
    codeChallenge?: string;
    resource?: string;
  }): { code: string; scopes: SupportedScopeDto[]; resource: URL } {
    const scopes = this.parseScopes(input.scope);
    const resource = this.resolveResource(input.resource);
    const code = randomUUID();

    this.store.setAuthorizationCode({
      code,
      clientId: input.client.client_id,
      redirectUri: input.redirectUri,
      codeChallenge: input.codeChallenge,
      scopes,
      resource,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });

    return {
      code,
      scopes,
      resource,
    };
  }

  validateAuthorizationRequest(input: { scope?: string; resource?: string }): void {
    this.parseScopes(input.scope);
    this.resolveResource(input.resource);
  }

  private parseScopes(scope?: string, allowedScopes?: SupportedScopeDto[]): SupportedScopeDto[] {
    const requestedScopes = scope?.trim() ? scope.trim().split(/\s+/) : ['mcp:tools'];
    const allowedScopeSet = new Set(allowedScopes ?? SUPPORTED_SCOPES);

    for (const requestedScope of requestedScopes) {
      if (!this.allowedScopes.has(requestedScope as SupportedScopeDto) || !allowedScopeSet.has(requestedScope as SupportedScopeDto)) {
        throw new InvalidScopeError(`Unsupported scope: ${requestedScope}`);
      }
    }

    if (!requestedScopes.includes('mcp:tools')) {
      requestedScopes.unshift('mcp:tools');
    }

    return [...new Set(requestedScopes)] as SupportedScopeDto[];
  }

  private resolveResource(resource?: string): URL {
    if (!resource) {
      return resourceUrlFromServerUrl(this.config.resourceServerUrl);
    }

    const requestedResource = new URL(resource);
    const configuredResource = resourceUrlFromServerUrl(this.config.resourceServerUrl);

    if (requestedResource.href !== configuredResource.href) {
      throw new InvalidTargetError('Invalid resource');
    }

    return requestedResource;
  }

  private issueTokens(input: {
    clientId: string;
    scopes: SupportedScopeDto[];
    resource: URL;
    issueRefreshToken: boolean;
  }): OAuthTokens {
    const accessToken = randomUUID();
    const accessTokenExpiresAt = Date.now() + this.config.accessTokenTtlSeconds * 1000;

    this.store.setAccessToken({
      token: accessToken,
      clientId: input.clientId,
      scopes: input.scopes,
      resource: input.resource,
      expiresAt: accessTokenExpiresAt,
    });

    const response: OAuthTokens = {
      access_token: accessToken,
      token_type: 'bearer',
      expires_in: this.config.accessTokenTtlSeconds,
      scope: input.scopes.join(' '),
    };

    if (input.issueRefreshToken) {
      const refreshToken = randomUUID();
      const refreshTokenExpiresAt = Date.now() + this.config.refreshTokenTtlSeconds * 1000;

      this.store.setRefreshToken({
        token: refreshToken,
        clientId: input.clientId,
        scopes: input.scopes,
        resource: input.resource,
        expiresAt: refreshTokenExpiresAt,
      });

      response.refresh_token = refreshToken;
    }

    return response;
  }
}

function escapeHtml(value: string): string {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function createCodeChallenge(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}

const tokenRequestSchema = z
  .object({
    grant_type: z.enum(['authorization_code', 'refresh_token']),
    client_id: z.string(),
    client_secret: z.string().optional(),
    code: z.string().optional(),
    code_verifier: z.string().optional(),
    redirect_uri: z.string().url().optional(),
    refresh_token: z.string().optional(),
    resource: z.string().url().optional(),
    scope: z.string().optional(),
  })
  .superRefine((value, ctx) => {
    if (value.grant_type === 'authorization_code' && !value.code) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['code'],
        message: 'code is required for authorization_code grant',
      });
    }

    if (value.grant_type === 'refresh_token' && !value.refresh_token) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['refresh_token'],
        message: 'refresh_token is required for refresh_token grant',
      });
    }
  });

function parseTokenRequest(source: unknown) {
  const parsed = tokenRequestSchema.safeParse(source);

  if (!parsed.success) {
    throw new InvalidRequestError(parsed.error.message);
  }

  return parsed.data;
}

function buildHiddenInput(name: keyof LoginFormDto, value: string | undefined): string {
  if (!value) {
    return '';
  }

  return `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`;
}

function renderLoginPage(res: Response, form: LoginFormDto, resourceName: string, errorMessage?: string): void {
  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(resourceName)} OAuth Login</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f4efe4;
        --panel: rgba(255, 252, 247, 0.94);
        --ink: #1f2a1f;
        --muted: #5f6d5f;
        --accent: #2f6f57;
        --accent-dark: #214d3d;
        --danger: #9d2b2b;
        --border: rgba(47, 111, 87, 0.18);
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
        color: var(--ink);
        background:
          radial-gradient(circle at top left, rgba(47, 111, 87, 0.22), transparent 32%),
          radial-gradient(circle at bottom right, rgba(166, 98, 55, 0.18), transparent 35%),
          linear-gradient(160deg, #ede3d1 0%, var(--bg) 100%);
        display: grid;
        place-items: center;
        padding: 24px;
      }
      .card {
        width: min(440px, 100%);
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 24px;
        padding: 28px;
        box-shadow: 0 24px 80px rgba(43, 54, 43, 0.16);
        backdrop-filter: blur(16px);
      }
      h1 {
        margin: 0 0 10px;
        font-size: 1.9rem;
        line-height: 1.05;
      }
      p {
        margin: 0 0 18px;
        color: var(--muted);
        line-height: 1.45;
      }
      .error {
        margin: 0 0 18px;
        padding: 12px 14px;
        border-radius: 14px;
        background: rgba(157, 43, 43, 0.08);
        color: var(--danger);
        font-size: 0.95rem;
      }
      label {
        display: block;
        margin: 0 0 8px;
        font-size: 0.92rem;
        color: var(--ink);
      }
      input {
        width: 100%;
        margin: 0 0 16px;
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 13px 14px;
        font: inherit;
        background: rgba(255, 255, 255, 0.9);
        color: var(--ink);
      }
      button {
        width: 100%;
        border: 0;
        border-radius: 999px;
        padding: 14px 18px;
        font: inherit;
        font-weight: 700;
        letter-spacing: 0.01em;
        color: white;
        background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dark) 100%);
        cursor: pointer;
      }
      .meta {
        margin-top: 16px;
        font-size: 0.82rem;
        color: var(--muted);
      }
      code {
        font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        font-size: 0.82rem;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <h1>Authorize ${escapeHtml(resourceName)}</h1>
      <p>Sign in to allow ChatGPT Developer Mode to call this Garmin MCP server on your behalf.</p>
      ${errorMessage ? `<div class="error">${escapeHtml(errorMessage)}</div>` : ''}
      <form method="post" action="/authorize">
        ${buildHiddenInput('client_id', form.client_id)}
        ${buildHiddenInput('redirect_uri', form.redirect_uri)}
        ${buildHiddenInput('response_type', form.response_type)}
        ${buildHiddenInput('code_challenge', form.code_challenge)}
        ${buildHiddenInput('code_challenge_method', form.code_challenge_method)}
        ${buildHiddenInput('scope', form.scope)}
        ${buildHiddenInput('state', form.state)}
        ${buildHiddenInput('resource', form.resource)}
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" required value="${escapeHtml(form.username ?? '')}">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required>
        <button type="submit">Authorize</button>
      </form>
      <div class="meta">
        Requested scopes: <code>${escapeHtml(form.scope ?? 'mcp:tools')}</code>
      </div>
    </main>
  </body>
</html>`;

  res.status(errorMessage ? 401 : 200).setHeader('Content-Type', 'text/html; charset=utf-8').send(html);
}

function createErrorRedirect(redirectUri: string, error: OAuthError, state?: string): string {
  const errorUrl = new URL(redirectUri);

  errorUrl.searchParams.set('error', error.errorCode);
  errorUrl.searchParams.set('error_description', error.message);

  if (state) {
    errorUrl.searchParams.set('state', state);
  }

  return errorUrl.href;
}

function parseLoginForm(source: unknown): LoginFormDto {
  const parsed = loginFormSchema.safeParse(source);

  if (!parsed.success) {
    throw new InvalidRequestError(parsed.error.message);
  }

  return parsed.data;
}

function handleOAuthError(res: Response, error: unknown): void {
  if (error instanceof OAuthError) {
    const status = error instanceof ServerError ? 500 : 400;
    res.status(status).json(error.toResponseObject());
    return;
  }

  const serverError = new ServerError('Internal Server Error');
  res.status(500).json(serverError.toResponseObject());
}

export function registerOAuthRoutes(app: Express, config: OAuthConfigDto): LocalOAuthProvider {
  const provider = new LocalOAuthProvider(config);

  app.use(express.urlencoded({ extended: false }));

  app.get('/authorize', async (req, res) => {
    try {
      const form = parseLoginForm(req.query);
      const client = await provider.getClient(form.client_id);
      const redirectUri = provider.resolveRedirectUri(client, form.redirect_uri);

      provider.validateAuthorizationRequest({
        scope: form.scope,
        resource: form.resource,
      });
      renderLoginPage(
        res,
        {
          ...form,
          redirect_uri: redirectUri,
        },
        config.resourceName,
      );
    } catch (error) {
      handleOAuthError(res, error);
    }
  });

  app.post('/authorize', async (req, res) => {
    let form: LoginFormDto | undefined;
    let redirectUri: string | undefined;

    try {
      form = parseLoginForm(req.body);
      const client = await provider.getClient(form.client_id);

      redirectUri = provider.resolveRedirectUri(client, form.redirect_uri);

      if (!provider.validateCredentials(form.username, form.password)) {
        renderLoginPage(
          res,
          {
            ...form,
            redirect_uri: redirectUri,
            password: undefined,
          },
          config.resourceName,
          'Invalid username or password',
        );
        return;
      }

      const authorization = provider.createAuthorizationCode({
        client,
        redirectUri,
        scope: form.scope,
        codeChallenge: form.code_challenge,
        resource: form.resource,
      });
      const successUrl = new URL(redirectUri);

      successUrl.searchParams.set('code', authorization.code);

      if (form.state) {
        successUrl.searchParams.set('state', form.state);
      }

      res.redirect(302, successUrl.href);
    } catch (error) {
      if (error instanceof OAuthError && redirectUri) {
        res.redirect(302, createErrorRedirect(redirectUri, error, form?.state));
        return;
      }

      handleOAuthError(res, error);
    }
  });

  app.post('/token', async (req, res) => {
    try {
      const request = parseTokenRequest(req.body);
      const client = await provider.getClient(request.client_id);

      if ((client.token_endpoint_auth_method ?? 'none') !== 'none') {
        throw new InvalidClientError('Only public OAuth clients are currently supported');
      }

      if (request.grant_type === 'authorization_code') {
        const tokens = await provider.exchangeAuthorizationCode(
          client,
          request.code as string,
          request.code_verifier,
          request.redirect_uri,
          request.resource ? new URL(request.resource) : undefined,
        );

        res.setHeader('Cache-Control', 'no-store');
        res.status(200).json(tokens);
        return;
      }

      const scopes = request.scope?.trim() ? request.scope.trim().split(/\s+/) : undefined;
      const tokens = await provider.exchangeRefreshToken(
        client,
        request.refresh_token as string,
        scopes,
        request.resource ? new URL(request.resource) : undefined,
      );

      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json(tokens);
    } catch (error) {
      handleOAuthError(res, error);
    }
  });

  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: config.issuerUrl,
      resourceServerUrl: config.resourceServerUrl,
      resourceName: config.resourceName,
      scopesSupported: [...SUPPORTED_SCOPES],
    }),
  );

  return provider;
}

export function createOAuthMiddleware(provider: OAuthServerProvider, resourceServerUrl: URL) {
  return requireBearerAuth({
    verifier: provider,
    requiredScopes: ['mcp:tools'],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
  });
}
