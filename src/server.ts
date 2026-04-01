import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GarminClient } from './client';
import {
  registerActivityTools,
  registerHealthTools,
  registerTrendTools,
  registerSleepTools,
  registerBodyTools,
  registerPerformanceTools,
  registerProfileTools,
  registerRangeTools,
  registerSnapshotTools,
  registerTrainingTools,
  registerWellnessTools,
  registerChallengeTools,
  registerWriteTools,
} from './tools';

export function createGarminMcpServer(email: string, password: string): McpServer {
  const server = new McpServer({
    name: 'garmin-connect-mcp',
    version: '1.1.0',
  });

  const client = new GarminClient(email, password);

  registerActivityTools(server, client);
  registerHealthTools(server, client);
  registerTrendTools(server, client);
  registerSleepTools(server, client);
  registerBodyTools(server, client);
  registerPerformanceTools(server, client);
  registerProfileTools(server, client);
  registerRangeTools(server, client);
  registerSnapshotTools(server, client);
  registerTrainingTools(server, client);
  registerWellnessTools(server, client);
  registerChallengeTools(server, client);
  registerWriteTools(server, client);

  return server;
}
