import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleGetBlacklist } from './handlers/blacklist.js';
import { checkTokenLimit } from './utils/token-limiter.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyTool = (name: string, desc: string, shape: unknown, cb: (args: unknown) => unknown) => void;

const GetBlacklistSchema = z.object({
  confidence_minimum: z
    .number()
    .int()
    .min(25)
    .max(100)
    .optional()
    .describe('Minimum abuse confidence score to include in blacklist (25–100, default: 90)'),
  limit: z
    .number()
    .int()
    .min(1)
    .max(500000)
    .optional()
    .describe('Maximum number of entries to return (default: all entries up to plan limit)'),
  plain_text: z
    .boolean()
    .optional()
    .describe('Return plain text IP list instead of JSON (default: false)'),
  break_token_rule: z
    .boolean()
    .optional()
    .default(false)
    .describe('Set to true to bypass token limits in critical situations (default: false)'),
});

export function registerBlacklistTools(server: McpServer, client: AxiosInstance, maxTokenCall = 20000): void {
  const registerTool = (server as any).tool.bind(server) as AnyTool;

  registerTool(
    'get_blacklist',
    'Retrieve the AbuseIPDB blacklist of most-reported malicious IP addresses. Returns confidence distribution, top countries, and sample entries. Requires AbuseIPDB subscription plan.',
    GetBlacklistSchema.shape,
    async (args: unknown) => {
      const parsed = GetBlacklistSchema.parse(args);
      const text = await handleGetBlacklist(client, parsed);
      const tokenCheck = checkTokenLimit(text, maxTokenCall, parsed.break_token_rule ?? false);
      if (!tokenCheck.allowed) {
        return { content: [{ type: 'text', text: tokenCheck.error! }] };
      }
      return { content: [{ type: 'text', text }] };
    }
  );
}
