import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleCheckBlock } from './handlers/block.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyTool = (name: string, desc: string, shape: unknown, cb: (args: unknown) => unknown) => void;

const CheckBlockSchema = z.object({
  network: z.string().describe('CIDR network block to check, e.g. "198.51.100.0/24"'),
  max_age_days: z
    .number()
    .int()
    .min(1)
    .max(365)
    .optional()
    .describe('Look-back window in days for abuse reports (1–365, default: 30)'),
  confidence_threshold: z
    .number()
    .int()
    .min(0)
    .max(100)
    .optional()
    .describe('Confidence % to classify addresses as high-confidence threats (default: 75)'),
});

export function registerBlockTools(server: McpServer, client: AxiosInstance): void {
  const registerTool = (server as any).tool.bind(server) as AnyTool;

  registerTool(
    'check_block',
    'Check all reported IP addresses within a CIDR network block against AbuseIPDB. Returns network summary, total reported addresses, and top threats sorted by confidence score. Requires AbuseIPDB subscription plan.',
    CheckBlockSchema.shape,
    async (args: unknown) => {
      const text = await handleCheckBlock(client, args as Parameters<typeof handleCheckBlock>[1]);
      return { content: [{ type: 'text', text }] };
    }
  );
}
