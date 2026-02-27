import { AxiosInstance } from 'axios';
import {
  IPCheckData,
  IPCheckResponse,
  assessRiskLevel,
  ABUSE_CATEGORIES,
} from '../types/abuseipdb.js';

export interface CheckIpArgs {
  ip_address: string;
  max_age_days?: number;
  verbose?: boolean;
  threshold?: number;
}

export interface BulkCheckArgs {
  ip_addresses: string[];
  max_age_days?: number;
  threshold?: number;
}

export async function handleCheckIp(
  client: AxiosInstance,
  args: CheckIpArgs
): Promise<string> {
  const { ip_address, max_age_days = 30, verbose = false, threshold = 75 } = args;

  const params: Record<string, unknown> = {
    ipAddress: ip_address,
    maxAgeInDays: max_age_days,
    verbose: verbose ? 'true' : 'false',
  };

  const { data: resp } = await client.get<IPCheckResponse>('/check', { params });
  const d: IPCheckData = resp.data;

  const riskLevel = assessRiskLevel(d.abuseConfidenceScore);
  const isFlagged = d.abuseConfidenceScore >= threshold;

  const lines = [
    `IP Address:        ${d.ipAddress}`,
    `Risk Level:        ${riskLevel}`,
    `Abuse Confidence:  ${d.abuseConfidenceScore}%`,
    `Total Reports:     ${d.totalReports}`,
    `Distinct Reporters:${d.numDistinctUsers}`,
    `Last Reported:     ${d.lastReportedAt ?? 'Never'}`,
    `Country:           ${d.countryName ?? d.countryCode ?? 'Unknown'}`,
    `ISP:               ${d.isp ?? 'Unknown'}`,
    `Domain:            ${d.domain ?? 'Unknown'}`,
    `Usage Type:        ${d.usageType ?? 'Unknown'}`,
    `Is Public:         ${d.isPublic}`,
    `Is Whitelisted:    ${d.isWhitelisted}`,
    `Is Tor:            ${d.isTor}`,
  ];

  if (isFlagged) lines.push(`\n⚠️  FLAGGED: Abuse confidence ${d.abuseConfidenceScore}% exceeds threshold of ${threshold}%`);
  if (d.isWhitelisted) lines.push('✅ Whitelisted');

  if (verbose && d.reports && d.reports.length > 0) {
    lines.push('\nRecent Reports (up to 10):');
    d.reports.slice(0, 10).forEach((r) => {
      const cats = r.categories.map((c) => ABUSE_CATEGORIES[c] ?? `Category ${c}`).join(', ');
      lines.push(`  • ${r.reportedAt} [${cats}] – ${r.comment || '(no comment)'}`);
    });
  }

  return lines.join('\n');
}

export async function handleBulkCheck(
  client: AxiosInstance,
  args: BulkCheckArgs
): Promise<string> {
  const { ip_addresses, max_age_days = 30, threshold = 75 } = args;

  if (!ip_addresses || ip_addresses.length === 0) throw new Error('ip_addresses list is required');
  if (ip_addresses.length > 100) throw new Error('Maximum 100 IP addresses per bulk check');

  const unique = [...new Set(ip_addresses.map((ip) => ip.trim()).filter(Boolean))];

  const results: Array<{
    ip: string;
    success: boolean;
    score?: number;
    country?: string | null;
    isp?: string | null;
    reports?: number;
    error?: string;
  }> = [];

  // Sequential requests to respect rate limits
  for (const ip of unique) {
    try {
      const { data: resp } = await client.get<IPCheckResponse>('/check', {
        params: { ipAddress: ip, maxAgeInDays: max_age_days, verbose: 'false' },
      });
      const d = resp.data;
      results.push({
        ip,
        success: true,
        score: d.abuseConfidenceScore,
        country: d.countryName ?? d.countryCode,
        isp: d.isp,
        reports: d.totalReports,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      results.push({ ip, success: false, error: msg });
    }
  }

  const successful = results.filter((r) => r.success);
  const failed = results.filter((r) => !r.success);
  const flagged = successful.filter((r) => (r.score ?? 0) >= threshold);

  const lines = [
    `Bulk Check Results:`,
    `  Unique IPs processed: ${unique.length}`,
    `  Successful:           ${successful.length}`,
    `  Failed:               ${failed.length}`,
    `  Flagged (≥${threshold}%):       ${flagged.length}`,
  ];

  if (flagged.length > 0) {
    lines.push('\n⚠️  Flagged IPs:');
    flagged.slice(0, 20).forEach((r) => {
      lines.push(`  • ${r.ip} – ${r.score}% (${r.country ?? 'Unknown'}, ${r.reports} reports)`);
    });
    if (flagged.length > 20) lines.push(`  ... and ${flagged.length - 20} more`);
  }

  if (failed.length > 0) {
    lines.push('\n❌ Failed IPs:');
    failed.slice(0, 5).forEach((r) => lines.push(`  • ${r.ip}: ${r.error}`));
    if (failed.length > 5) lines.push(`  ... and ${failed.length - 5} more`);
  }

  lines.push('\nAll Results:');
  results.forEach((r) => {
    if (r.success) {
      const level = assessRiskLevel(r.score ?? 0);
      lines.push(`  ${r.ip} – ${level} (${r.score}%) – ${r.country ?? 'Unknown'} – ${r.isp ?? 'Unknown ISP'}`);
    } else {
      lines.push(`  ${r.ip} – ERROR: ${r.error}`);
    }
  });

  return lines.join('\n');
}
