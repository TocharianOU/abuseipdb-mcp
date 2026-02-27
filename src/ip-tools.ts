import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { z } from 'zod';
import { handleCheckIp, handleBulkCheck } from './handlers/ip.js';

// Note: server.tool is called via (server as any) cast to avoid TypeScript
// exceeding instantiation-depth limits when inferring Zod schema generics.

const CheckIpSchema = z.object({
  ip_address: z.string().describe('IPv4 or IPv6 address to check'),
  max_age_days: z
    .number()
    .int()
    .min(1)
    .max(365)
    .optional()
    .describe('Look-back window in days for abuse reports (1–365, default: 30)'),
  verbose: z
    .boolean()
    .optional()
    .describe('Include individual report details in the response (default: false)'),
  threshold: z
    .number()
    .int()
    .min(0)
    .max(100)
    .optional()
    .describe('Abuse confidence % threshold for flagging the IP (0–100, default: 75)'),
});

const BulkCheckSchema = z.object({
  ip_addresses: z
    .array(z.string())
    .min(1)
    .max(100)
    .describe('List of IPv4/IPv6 addresses to check (up to 100)'),
  max_age_days: z
    .number()
    .int()
    .min(1)
    .max(365)
    .optional()
    .describe('Look-back window in days (1–365, default: 30)'),
  threshold: z
    .number()
    .int()
    .min(0)
    .max(100)
    .optional()
    .describe('Abuse confidence % threshold for flagging (0–100, default: 75)'),
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyTool = (name: string, desc: string, shape: unknown, cb: (args: unknown) => unknown) => void;

export function registerIpTools(server: McpServer, client: AxiosInstance): void {
  const registerTool = (server as any).tool.bind(server) as AnyTool;

  registerTool(
    'check_ip',
    'Check the reputation of a single IP address using AbuseIPDB. Returns abuse confidence score (0–100%), risk level, ISP, country, total reports, and optional verbose report details.',
    CheckIpSchema.shape,
    (args: unknown) => handleCheckIp(client, args as Parameters<typeof handleCheckIp>[1])
  );

  registerTool(
    'bulk_check',
    'Check the reputation of multiple IP addresses in batch (up to 100). Returns a summary of flagged IPs with confidence scores, risk levels, and country/ISP information.',
    BulkCheckSchema.shape,
    (args: unknown) => handleBulkCheck(client, args as Parameters<typeof handleBulkCheck>[1])
  );
}
