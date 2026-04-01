import { randomUUID } from 'node:crypto';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { createMcpExpressApp } from '@modelcontextprotocol/sdk/server/express.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Express, Request, Response } from 'express';
import { createGarminMcpServer } from './server';
import { createOAuthMiddleware, registerOAuthRoutes, type OAuthConfigDto } from './oauth';

type TransportModeDto = 'stdio' | 'http';

type RuntimeConfigDto = {
  email: string;
  password: string;
  mode: TransportModeDto;
  host: string;
  port: number;
  path: string;
  publicBaseUrl?: URL;
  allowedHosts?: string[];
  oauth?: OAuthConfigDto;
};

type HttpSessionDto = {
  server: McpServer;
  transport: StreamableHTTPServerTransport;
};

function getRequiredEnv(name: string): string {
  const value = process.env[name]?.trim();

  if (value) {
    return value;
  }

  console.error(
    `Error: ${name} environment variable is required.\n` +
      'For local stdio usage:\n' +
      '  claude mcp add garmin -e GARMIN_EMAIL=you@email.com -e GARMIN_PASSWORD=yourpass -- npx -y @nicolasvegam/garmin-connect-mcp\n' +
      'For remote HTTP usage:\n' +
      '  GARMIN_EMAIL=you@email.com GARMIN_PASSWORD=yourpass MCP_TRANSPORT=http node build/index.js',
  );
  process.exit(1);
}

function resolveTransportMode(): TransportModeDto {
  const explicitMode = process.env.MCP_TRANSPORT?.trim().toLowerCase();

  if (explicitMode === 'http') {
    return 'http';
  }

  if (explicitMode === 'stdio') {
    return 'stdio';
  }

  if (process.env.PORT || process.env.MCP_PORT) {
    return 'http';
  }

  return 'stdio';
}

function parsePort(value: string | undefined): number {
  if (!value) {
    return 3000;
  }

  const port = Number.parseInt(value, 10);

  if (Number.isNaN(port) || port <= 0) {
    console.error(`Error: invalid port value "${value}"`);
    process.exit(1);
  }

  return port;
}

function normalizePath(value: string | undefined): string {
  const rawPath = value?.trim() || '/mcp';

  if (rawPath === '/') {
    return rawPath;
  }

  const prefixedPath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;

  return prefixedPath.replace(/\/+$/, '');
}

function parseCsv(value: string | undefined): string[] | undefined {
  const items = value
    ?.split(',')
    .map((item) => item.trim())
    .filter(Boolean);

  return items?.length ? items : undefined;
}

function parseUrl(value: string | undefined, name: string): URL | undefined {
  if (!value?.trim()) {
    return undefined;
  }

  try {
    return new URL(value);
  } catch {
    console.error(`Error: invalid URL for ${name}: "${value}"`);
    process.exit(1);
  }
}

function parseNumberEnv(value: string | undefined, name: string, defaultValue: number): number {
  if (!value?.trim()) {
    return defaultValue;
  }

  const parsedValue = Number.parseInt(value, 10);

  if (Number.isNaN(parsedValue) || parsedValue <= 0) {
    console.error(`Error: invalid numeric value for ${name}: "${value}"`);
    process.exit(1);
  }

  return parsedValue;
}

function buildOAuthConfig(publicBaseUrl: URL | undefined, path: string): OAuthConfigDto | undefined {
  const oauthEnabled = ['true', '1'].includes(process.env.MCP_OAUTH_ENABLED?.trim().toLowerCase() ?? '');

  if (!oauthEnabled) {
    return undefined;
  }

  if (!publicBaseUrl) {
    console.error('Error: MCP_PUBLIC_BASE_URL is required when MCP_OAUTH_ENABLED=true');
    process.exit(1);
  }

  const username = getRequiredEnv('MCP_OAUTH_USERNAME');
  const password = getRequiredEnv('MCP_OAUTH_PASSWORD');
  const resourceServerUrl = new URL(path, publicBaseUrl);

  return {
    issuerUrl: new URL(publicBaseUrl.href),
    resourceServerUrl,
    username,
    password,
    resourceName: process.env.MCP_OAUTH_RESOURCE_NAME?.trim() || 'Garmin Connect MCP',
    accessTokenTtlSeconds: parseNumberEnv(
      process.env.MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS,
      'MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS',
      3600,
    ),
    refreshTokenTtlSeconds: parseNumberEnv(
      process.env.MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS,
      'MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS',
      30 * 24 * 60 * 60,
    ),
  };
}

function getRuntimeConfig(): RuntimeConfigDto {
  const publicBaseUrl = parseUrl(process.env.MCP_PUBLIC_BASE_URL, 'MCP_PUBLIC_BASE_URL');
  const path = normalizePath(process.env.MCP_PATH);

  return {
    email: getRequiredEnv('GARMIN_EMAIL'),
    password: getRequiredEnv('GARMIN_PASSWORD'),
    mode: resolveTransportMode(),
    host: process.env.MCP_HOST?.trim() || '0.0.0.0',
    port: parsePort(process.env.PORT ?? process.env.MCP_PORT),
    path,
    publicBaseUrl,
    allowedHosts: parseCsv(process.env.MCP_ALLOWED_HOSTS),
    oauth: buildOAuthConfig(publicBaseUrl, path),
  };
}

function sendJson(res: Response, statusCode: number, payload: unknown): void {
  res.status(statusCode).type('application/json').send(payload);
}

function sendJsonRpcError(res: Response, statusCode: number, errorCode: number, message: string): void {
  sendJson(res, statusCode, {
    jsonrpc: '2.0',
    error: {
      code: errorCode,
      message,
    },
    id: null,
  });
}

async function closeSession(sessions: Map<string, HttpSessionDto>, sessionId: string): Promise<void> {
  const session = sessions.get(sessionId);

  if (!session) {
    return;
  }

  sessions.delete(sessionId);
  await session.server.close();
}

async function handlePostRequest(
  req: Request,
  res: Response,
  sessions: Map<string, HttpSessionDto>,
  config: RuntimeConfigDto,
): Promise<void> {
  const sessionId = typeof req.headers['mcp-session-id'] === 'string' ? req.headers['mcp-session-id'] : undefined;

  if (sessionId) {
    const existingSession = sessions.get(sessionId);

    if (!existingSession) {
      sendJsonRpcError(res, 404, -32001, 'Session not found');
      return;
    }

    await existingSession.transport.handleRequest(req, res, req.body);
    return;
  }

  if (!isInitializeRequest(req.body)) {
    sendJsonRpcError(res, 400, -32000, 'Bad Request: No valid session ID provided');
    return;
  }

  let session: HttpSessionDto | undefined;
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (createdSessionId) => {
      if (session) {
        sessions.set(createdSessionId, session);
      }
    },
  });
  const server = createGarminMcpServer(config.email, config.password);

  session = { server, transport };
  transport.onclose = () => {
    const createdSessionId = transport.sessionId;

    if (createdSessionId) {
      sessions.delete(createdSessionId);
    }
  };
  transport.onerror = (error) => {
    console.error('MCP transport error:', error);
  };

  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    const createdSessionId = transport.sessionId;

    if (createdSessionId) {
      sessions.delete(createdSessionId);
    }

    await server.close();
    throw error;
  }
}

async function handleGetRequest(req: Request, res: Response, sessions: Map<string, HttpSessionDto>): Promise<void> {
  const sessionId = typeof req.headers['mcp-session-id'] === 'string' ? req.headers['mcp-session-id'] : undefined;

  if (!sessionId) {
    sendJsonRpcError(res, 400, -32000, 'Missing MCP session ID');
    return;
  }

  const session = sessions.get(sessionId);

  if (!session) {
    sendJsonRpcError(res, 404, -32001, 'Session not found');
    return;
  }

  await session.transport.handleRequest(req, res);
}

async function handleDeleteRequest(req: Request, res: Response, sessions: Map<string, HttpSessionDto>): Promise<void> {
  const sessionId = typeof req.headers['mcp-session-id'] === 'string' ? req.headers['mcp-session-id'] : undefined;

  if (!sessionId) {
    sendJsonRpcError(res, 400, -32000, 'Missing MCP session ID');
    return;
  }

  const session = sessions.get(sessionId);

  if (!session) {
    sendJsonRpcError(res, 404, -32001, 'Session not found');
    return;
  }

  await session.transport.handleRequest(req, res);
}

function registerHttpRoutes(app: Express, config: RuntimeConfigDto, sessions: Map<string, HttpSessionDto>): void {
  const oauthProvider = config.oauth ? registerOAuthRoutes(app, config.oauth) : undefined;
  const oauthMiddleware =
    oauthProvider && config.oauth ? createOAuthMiddleware(oauthProvider, config.oauth.resourceServerUrl) : undefined;

  app.get('/', (_req, res) => {
    sendJson(res, 200, {
      name: 'garmin-connect-mcp',
      transport: 'streamable-http',
      endpoint: config.publicBaseUrl ? new URL(config.path, config.publicBaseUrl).href : config.path,
      health: '/health',
      authentication: config.oauth ? 'oauth' : 'none',
    });
  });

  app.get('/health', (_req, res) => {
    sendJson(res, 200, { ok: true });
  });

  if (oauthMiddleware) {
    app.use(config.path, oauthMiddleware);
  }

  app.post(config.path, async (req, res) => {
    try {
      await handlePostRequest(req, res, sessions, config);
    } catch (error) {
      console.error('Error handling MCP POST request:', error);

      if (!res.headersSent) {
        sendJsonRpcError(res, 500, -32603, 'Internal server error');
      }
    }
  });

  app.get(config.path, async (req, res) => {
    try {
      await handleGetRequest(req, res, sessions);
    } catch (error) {
      console.error('Error handling MCP GET request:', error);

      if (!res.headersSent) {
        sendJsonRpcError(res, 500, -32603, 'Internal server error');
      }
    }
  });

  app.delete(config.path, async (req, res) => {
    try {
      await handleDeleteRequest(req, res, sessions);
    } catch (error) {
      console.error('Error handling MCP DELETE request:', error);

      if (!res.headersSent) {
        sendJsonRpcError(res, 500, -32603, 'Internal server error');
      }
    }
  });
}

async function shutdownHttpServer(
  sessions: Map<string, HttpSessionDto>,
  httpServer: { close: (callback: (error?: Error) => void) => void },
): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    httpServer.close((error?: Error) => {
      if (error) {
        reject(error);
        return;
      }

      resolve();
    });
  });

  for (const sessionId of [...sessions.keys()]) {
    await closeSession(sessions, sessionId);
  }
}

async function startHttpServer(config: RuntimeConfigDto): Promise<void> {
  const sessions = new Map<string, HttpSessionDto>();
  const app = createMcpExpressApp({
    host: config.host,
    allowedHosts: config.allowedHosts,
  });

  registerHttpRoutes(app, config, sessions);

  const httpServer = await new Promise<ReturnType<Express['listen']>>((resolve, reject) => {
    const server = app.listen(config.port, config.host, () => resolve(server));

    server.once('error', reject);
  });

  console.error(
    `Garmin Connect MCP server running on streamable HTTP at http://${config.host}:${config.port}${config.path}`,
  );

  if (config.oauth) {
    console.error(`OAuth authorization server enabled at ${config.oauth.issuerUrl.href}`);
  }

  const handleShutdown = (signal: string) => {
    console.error(`Received ${signal}, shutting down HTTP server`);
    void shutdownHttpServer(sessions, httpServer)
      .catch((error) => {
        console.error('Error during HTTP shutdown:', error);
      })
      .finally(() => {
        process.exit(0);
      });
  };

  process.once('SIGINT', () => handleShutdown('SIGINT'));
  process.once('SIGTERM', () => handleShutdown('SIGTERM'));
}

async function startStdioServer(config: RuntimeConfigDto): Promise<void> {
  const server = createGarminMcpServer(config.email, config.password);
  const transport = new StdioServerTransport();

  await server.connect(transport);
  console.error('Garmin Connect MCP server running on stdio');
}

async function main(): Promise<void> {
  const config = getRuntimeConfig();

  if (config.mode === 'http') {
    await startHttpServer(config);
    return;
  }

  await startStdioServer(config);
}

main().catch((error) => {
  console.error('Fatal error starting server:', error);
  process.exit(1);
});
