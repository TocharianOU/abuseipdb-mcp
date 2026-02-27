export interface ReportEntry {
  reportedAt: string;
  comment: string;
  categories: number[];
  reporterId: number;
  reporterCountryCode: string;
  reporterCountryName: string;
}

export interface IPCheckData {
  ipAddress: string;
  isPublic: boolean;
  ipVersion: number;
  isWhitelisted: boolean;
  abuseConfidenceScore: number;
  countryCode: string | null;
  countryName: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  hostnames: string[];
  isTor: boolean;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
  reports?: ReportEntry[];
}

export interface IPCheckResponse {
  data: IPCheckData;
}

export interface BlockAddressEntry {
  ipAddress: string;
  numReports: number;
  mostRecentReport: string | null;
  abuseConfidencePercentage: number;
  countryCode: string | null;
}

export interface BlockCheckData {
  networkAddress: string;
  netmask: string;
  minAddress: string;
  maxAddress: string;
  numPossibleHosts: number;
  addressSpaceDesc: string;
  reportedAddress: BlockAddressEntry[];
}

export interface BlockCheckResponse {
  data: BlockCheckData;
}

export interface BlacklistEntry {
  ipAddress: string;
  abuseConfidenceScore: number;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  domain: string | null;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt: string | null;
}

export interface BlacklistMeta {
  generatedAt: string;
}

export interface BlacklistResponse {
  meta: BlacklistMeta;
  data: BlacklistEntry[];
}

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';

export function assessRiskLevel(score: number): RiskLevel {
  if (score >= 90) return 'CRITICAL';
  if (score >= 75) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  if (score >= 1) return 'LOW';
  return 'CLEAN';
}

export const ABUSE_CATEGORIES: Record<number, string> = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
};
