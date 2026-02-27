import axios, { AxiosInstance } from 'axios';
import { AbuseIPDBConfig } from '../types.js';

const DEFAULT_BASE_URL = 'https://api.abuseipdb.com/api/v2';

/**
 * Creates an Axios client for AbuseIPDB.
 *
 * Auth strategy:
 *   BYOK mode  → apiKey present → sends `Key: <apiKey>` header (AbuseIPDB native auth)
 *   Hub mode   → no apiKey, baseUrl points to proxy → sends `Authorization: Bearer <authToken>`
 */
export function createAbuseIPDBClient(config: AbuseIPDBConfig): AxiosInstance {
  const baseURL = config.baseUrl || DEFAULT_BASE_URL;

  const headers: Record<string, string> = {
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  if (config.apiKey) {
    // BYOK: AbuseIPDB uses "Key" header for authentication
    headers['Key'] = config.apiKey;
  } else if (config.authToken) {
    // Hub proxy: authenticate with Bearer token; proxy injects the real API key
    headers['Authorization'] = `Bearer ${config.authToken}`;
  }

  return axios.create({
    baseURL,
    headers,
    timeout: config.timeout ?? 30000,
  });
}
