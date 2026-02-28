#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 TocharianOU Contributors

import 'dotenv/config';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { randomUUID } from 'crypto';
import { AbuseIPDBConfig, AbuseIPDBConfigSchema } from './src/types.js';
import { createAbuseIPDBClient } from './src/utils/api.js';
import { registerIpTools } from './src/ip-tools.js';
import { registerBlockTools } from './src/block-tools.js';
import { registerBlacklistTools } from './src/blacklist-tools.js';

interface ServerCreationOptions {
  name: string;
  version: string;
  config: AbuseIPDBConfig;
  description?: string;
}

export async function createAbuseIPDBMcpServer(options: ServerCreationOptions): Promise<McpServer> {
  const { name, version, config, description } = options;

  const validatedConfig = AbuseIPDBConfigSchema.parse(config);
  const client = createAbuseIPDBClient(validatedConfig);

  const server = new McpServer({
    name,
    version,
    ...(description ? { description } : {}),
  });

  const maxTokenCall = parseInt(process.env.MAX_TOKEN_CALL ?? '20000', 10);

  registerIpTools(server, client, maxTokenCall);
  registerBlockTools(server, client, maxTokenCall);
  registerBlacklistTools(server, client, maxTokenCall);

  return server;
}

async function main(): Promise<void> {
  const config: AbuseIPDBConfig = {
    apiKey: process.env.ABUSEIPDB_API_KEY,
    baseUrl: process.env.ABUSEIPDB_BASE_URL,
    authToken: process.env.ABUSEIPDB_AUTH_TOKEN,
    timeout: parseInt(process.env.ABUSEIPDB_TIMEOUT ?? '30000', 10),
  };

  const SERVER_NAME = 'abuseipdb-mcp-server';
  const SERVER_VERSION = '1.0.0';
  const SERVER_DESCRIPTION =
    'AbuseIPDB MCP Server – IP reputation, abuse confidence scoring, and threat blacklist';

  const useHttp = process.env.MCP_TRANSPORT === 'http';
  const httpPort = parseInt(process.env.MCP_HTTP_PORT ?? '3000', 10);
  const httpHost = process.env.MCP_HTTP_HOST ?? 'localhost';

  if (useHttp) {
    process.stderr.write(
      `Starting AbuseIPDB MCP Server in HTTP mode on ${httpHost}:${httpPort}\n`
    );

    const app = express();
    app.use(express.json());

    const transports = new Map<string, StreamableHTTPServerTransport>();

    app.get('/health', (_req, res) => {
      res.json({ status: 'ok', transport: 'streamable-http' });
    });

    app.post('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      try {
        let transport: StreamableHTTPServerTransport;

        if (sessionId !== undefined && transports.has(sessionId)) {
          transport = transports.get(sessionId)!;
        } else {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: async (newSessionId: string) => {
              transports.set(newSessionId, transport);
              process.stderr.write(`MCP session initialized: ${newSessionId}\n`);
            },
            onsessionclosed: async (closedSessionId: string) => {
              transports.delete(closedSessionId);
              process.stderr.write(`MCP session closed: ${closedSessionId}\n`);
            },
          });

          const server = await createAbuseIPDBMcpServer({
            name: SERVER_NAME,
            version: SERVER_VERSION,
            config,
            description: SERVER_DESCRIPTION,
          });

          await server.connect(transport);
        }

        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        process.stderr.write(`Error handling MCP request: ${error}\n`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      }
    });

    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      if (sessionId === undefined || !transports.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Invalid or missing session ID' },
          id: null,
        });
        return;
      }

      try {
        const transport = transports.get(sessionId)!;
        await transport.handleRequest(req, res);
      } catch (error) {
        process.stderr.write(`Error handling SSE stream: ${error}\n`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Failed to establish SSE stream' },
            id: null,
          });
        }
      }
    });

    app.listen(httpPort, httpHost, () => {
      process.stderr.write(
        `AbuseIPDB MCP Server (HTTP mode) started on http://${httpHost}:${httpPort}\n`
      );
    });

    process.on('SIGINT', async () => {
      for (const [, transport] of transports.entries()) {
        await transport.close();
      }
      process.exit(0);
    });
  } else {
    process.stderr.write('Starting AbuseIPDB MCP Server in Stdio mode\n');

    const server = await createAbuseIPDBMcpServer({
      name: SERVER_NAME,
      version: SERVER_VERSION,
      config,
      description: SERVER_DESCRIPTION,
    });

    const transport = new StdioServerTransport();
    await server.connect(transport);

    process.on('SIGINT', async () => {
      await server.close();
      process.exit(0);
    });
  }
}

main().catch((error: unknown) => {
  process.stderr.write(
    `Fatal error: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exit(1);
});
