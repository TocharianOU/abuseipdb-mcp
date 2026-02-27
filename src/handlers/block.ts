import { AxiosInstance } from 'axios';
import { BlockCheckResponse } from '../types/abuseipdb.js';

export interface CheckBlockArgs {
  network: string;
  max_age_days?: number;
  confidence_threshold?: number;
}

export async function handleCheckBlock(
  client: AxiosInstance,
  args: CheckBlockArgs
): Promise<string> {
  const { network, max_age_days = 30, confidence_threshold = 75 } = args;

  const { data: resp } = await client.get<BlockCheckResponse>('/check-block', {
    params: { network, maxAgeInDays: max_age_days },
  });

  const d = resp.data;
  const reported = d.reportedAddress ?? [];
  const highConfidence = reported.filter(
    (a) => a.abuseConfidencePercentage >= confidence_threshold
  );

  const lines = [
    `Network:           ${d.networkAddress}/${d.netmask}`,
    `Address Range:     ${d.minAddress} – ${d.maxAddress}`,
    `Possible Hosts:    ${d.numPossibleHosts.toLocaleString()}`,
    `Address Space:     ${d.addressSpaceDesc}`,
    `Reported IPs:      ${reported.length}`,
    `High Confidence:   ${highConfidence.length} (≥${confidence_threshold}%)`,
  ];

  if (highConfidence.length > 0) {
    lines.push(`\n⚠️  ${highConfidence.length} high-confidence threats detected in this block`);
  }

  if (reported.length > 0) {
    lines.push('\nTop Reported Addresses:');
    const sorted = [...reported].sort(
      (a, b) => b.abuseConfidencePercentage - a.abuseConfidencePercentage
    );
    sorted.slice(0, 10).forEach((a) => {
      lines.push(
        `  • ${a.ipAddress} – ${a.abuseConfidencePercentage}% confidence (${a.numReports} reports, last: ${a.mostRecentReport ?? 'Unknown'})`
      );
    });
    if (reported.length > 10) lines.push(`  ... and ${reported.length - 10} more`);
  } else {
    lines.push('\n✅ No reported IP addresses found in this block');
  }

  return lines.join('\n');
}
