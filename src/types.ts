import { z } from 'zod';

export const AbuseIPDBConfigSchema = z.object({
  apiKey: z
    .string()
    .optional()
    .describe(
      'AbuseIPDB API key sent as Key header (BYOK mode). ' +
        'Get yours at https://www.abuseipdb.com/account/api'
    ),
  baseUrl: z
    .string()
    .optional()
    .describe(
      'Override the AbuseIPDB API base URL. ' +
        'Defaults to https://api.abuseipdb.com/api/v2. ' +
        'Set this to a proxy endpoint to route requests through a backend.'
    ),
  authToken: z
    .string()
    .optional()
    .describe(
      'Bearer token sent as Authorization header when using a proxy base URL. ' +
        'Ignored when apiKey is set directly.'
    ),
  timeout: z.number().optional().default(30000).describe('Request timeout in milliseconds'),
});

export type AbuseIPDBConfig = z.infer<typeof AbuseIPDBConfigSchema>;
