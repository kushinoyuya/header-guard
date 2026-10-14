export type Severity = 'info' | 'low' | 'medium' | 'high';

export interface Finding {
  /** Stable identifier, usable with `ignore` / `--ignore`. */
  id: string;
  severity: Severity;
  title: string;
  /** What was observed. */
  detail: string;
  /** How to fix it. */
  fix: string;
}

export type HeaderInput =
  | Record<string, string | string[] | number | undefined>
  | Map<string, string | string[]>
  | { entries(): Iterable<[string, string]> };

export interface AuditOptions {
  /** URL the response came from; used to detect HTTPS and localhost. */
  url?: string | URL;
  /** Override TLS detection. */
  https?: boolean;
  /** Finding ids to suppress. */
  ignore?: string[];
  /** Drop findings below this level. */
  minSeverity?: Severity;
}

export interface FetchOptions {
  /** Per-request timeout in ms. Default 10000. */
  timeout?: number;
  /** Default true. */
  followRedirects?: boolean;
  /** Default 5. */
  maxRedirects?: number;
  /** Extra request headers, e.g. a session cookie. */
  headers?: Record<string, string>;
  /** Accept invalid TLS certificates (local development only). */
  insecure?: boolean;
}

export interface FetchResult {
  url: string;
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  redirects: string[];
}

export interface Report {
  url?: string;
  statusCode?: number | null;
  redirects?: string[];
  findings: Finding[];
}

export interface Summary {
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** Audit response headers. Pure, no I/O. Findings are sorted worst first. */
export function audit(headers: HeaderInput, options?: AuditOptions): Finding[];

/** Fetch a URL (following redirects) and audit the final response. */
export function auditUrl(
  url: string,
  options?: FetchOptions & Pick<AuditOptions, 'ignore' | 'minSeverity'>
): Promise<Required<Report>>;

export function summarize(findings: Finding[]): Summary;
export function fetchHeaders(url: string, options?: FetchOptions): Promise<FetchResult>;

export function parseCsp(header: string | string[]): Array<Record<string, string[]>>;
export function parseRawHeaders(text: string): { statusCode: number | null; headers: Record<string, string[]> };
export function parseSetCookie(header: string): {
  name: string;
  value: string;
  attributes: Record<string, string | true>;
};
export function normalizeHeaders(input: HeaderInput): Record<string, string[]>;

export function formatText(report: Report, options?: { color?: boolean }): string;
export function formatJson(report: Report): string;

export const SEVERITIES: Severity[];
