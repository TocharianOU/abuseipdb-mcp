import { AxiosInstance } from 'axios';
import { BlacklistResponse, assessRiskLevel } from '../types/abuseipdb.js';

export interface GetBlacklistArgs {
  confidence_minimum?: number;
  limit?: number;
  plain_text?: boolean;
}

export async function handleGetBlacklist(
  client: AxiosInstance,
  args: GetBlacklistArgs
): Promise<string> {
  const { confidence_minimum = 90, limit, plain_text = false } = args;

  const params: Record<string, unknown> = { confidenceMinimum: confidence_minimum };
  if (limit !== undefined) params['limit'] = limit;
  if (plain_text) params['plaintext'] = true;

  const { data: resp } = await client.get<BlacklistResponse>('/blacklist', { params });

  const entries = resp.data ?? [];
  const generatedAt = resp.meta?.generatedAt ?? 'Unknown';

  const countryStats: Record<string, number> = {};
  const confidenceDist = { '90-100': 0, '75-89': 0, '50-74': 0, '0-49': 0 };

  for (const e of entries) {
    const cc = e.countryCode ?? 'Unknown';
    countryStats[cc] = (countryStats[cc] ?? 0) + 1;

    const s = e.abuseConfidenceScore;
    if (s >= 90) confidenceDist['90-100']++;
    else if (s >= 75) confidenceDist['75-89']++;
    else if (s >= 50) confidenceDist['50-74']++;
    else confidenceDist['0-49']++;
  }

  const topCountries = Object.entries(countryStats)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 10);

  const lines = [
    `Blacklist Retrieved: ${entries.length.toLocaleString()} entries`,
    `Generated:           ${generatedAt}`,
    `Minimum Confidence:  ${confidence_minimum}%`,
  ];

  if (limit !== undefined) lines.push(`Limit Applied:       ${limit.toLocaleString()}`);

  lines.push(
    '\nConfidence Distribution:',
    `  • 90-100%: ${confidenceDist['90-100'].toLocaleString()}`,
    `  • 75-89%:  ${confidenceDist['75-89'].toLocaleString()}`,
    `  • 50-74%:  ${confidenceDist['50-74'].toLocaleString()}`,
    `  • 0-49%:   ${confidenceDist['0-49'].toLocaleString()}`
  );

  if (topCountries.length > 0) {
    lines.push('\nTop Countries:');
    topCountries.forEach(([cc, count]) => {
      lines.push(`  • ${cc}: ${count.toLocaleString()}`);
    });
  }

  if (entries.length > 0) {
    lines.push('\nSample Entries (top 20 by confidence):');
    const sorted = [...entries].sort((a, b) => b.abuseConfidenceScore - a.abuseConfidenceScore);
    sorted.slice(0, 20).forEach((e) => {
      const level = assessRiskLevel(e.abuseConfidenceScore);
      const last = e.lastReportedAt ? e.lastReportedAt.slice(0, 10) : 'Unknown';
      lines.push(
        `  • ${e.ipAddress} (${e.countryCode ?? '?'}) – ${e.abuseConfidenceScore}% [${level}] – last: ${last}`
      );
    });
    if (entries.length > 20) lines.push(`  ... and ${entries.length - 20} more entries`);
  }

  return lines.join('\n');
}
