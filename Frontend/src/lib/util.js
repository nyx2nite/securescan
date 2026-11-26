export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

export const SEV_STYLE = {
  critical: { text: 'text-fuchsia-300', bg: 'bg-fuchsia-500/15', ring: 'ring-fuchsia-500/40', dot: 'bg-fuchsia-400', hex: '#e879f9' },
  high: { text: 'text-red-300', bg: 'bg-red-500/15', ring: 'ring-red-500/40', dot: 'bg-red-400', hex: '#f87171' },
  medium: { text: 'text-amber-300', bg: 'bg-amber-500/15', ring: 'ring-amber-500/40', dot: 'bg-amber-400', hex: '#fbbf24' },
  low: { text: 'text-sky-300', bg: 'bg-sky-500/15', ring: 'ring-sky-500/40', dot: 'bg-sky-400', hex: '#38bdf8' },
  info: { text: 'text-slate-300', bg: 'bg-slate-500/15', ring: 'ring-slate-500/40', dot: 'bg-slate-400', hex: '#94a3b8' },
};

export function risk(score) {
  if (score >= 90) return { key: 'excellent', label: 'Excellent', hex: '#22d3a6', text: 'text-emerald-300' };
  if (score >= 70) return { key: 'good', label: 'Good', hex: '#38bdf8', text: 'text-sky-300' };
  if (score >= 50) return { key: 'fair', label: 'Fair', hex: '#fbbf24', text: 'text-amber-300' };
  return { key: 'critical', label: 'Critical', hex: '#f87171', text: 'text-red-300' };
}

export const LEGACY_MAX = { https: 20, headers: 30, ports: 20, cookies: 15, config: 15 };
export const CATEGORY_LABELS = {
  https: 'HTTPS / TLS', headers: 'Security headers', ports: 'Network exposure',
  cookies: 'Cookies', config: 'Server config', dns: 'DNS & email',
};

export function findingsOf(scan) {
  const list = scan?.details?.vulnerabilities || [];
  return [...list].sort((a, b) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9));
}

export function severityCounts(findings) {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  findings.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
  return c;
}

export function fmtDate(d) {
  if (!d) return '';
  const date = new Date(d.endsWith?.('Z') || d.includes?.('+') ? d : d + 'Z');
  return date.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function timeAgo(d) {
  if (!d) return '';
  const date = new Date(d.endsWith?.('Z') ? d : d + 'Z');
  const s = Math.round((Date.now() - date.getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function titleOf(f) {
  return f.details?.title || f.type?.replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());
}
