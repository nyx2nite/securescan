import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, Gauge, Globe, Lock, ShieldAlert, TriangleAlert } from 'lucide-react';
import { api } from '../lib/api';
import { SEVERITIES, SEV_STYLE, findingsOf, risk, severityCounts, timeAgo, titleOf } from '../lib/util';
import { Card, CardHeader, Empty, ErrorBox, PageHeader, ScoreBadge, Spinner } from '../components/ui';

function Stat({ icon: Icon, label, value, sub, color }) {
  return (
    <Card className="p-5">
      <div className="flex items-center gap-2 text-xs text-muted"><Icon size={14} /> {label}</div>
      <div className="mt-2 text-3xl font-semibold tracking-tight" style={color ? { color } : undefined}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </Card>
  );
}

export default function Dashboard() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => { api('/scans').then(setScans).catch((e) => setError(e.message)); }, []);

  const data = useMemo(() => {
    if (!scans) return null;
    // Latest scan per target + previous score for trend
    const byDomain = new Map();
    for (const s of scans) {
      const entry = byDomain.get(s.domain);
      if (!entry) byDomain.set(s.domain, { latest: s, prev: null, count: 1 });
      else { entry.count += 1; if (!entry.prev) entry.prev = s; }
    }
    const targets = [...byDomain.values()];
    const latestFindings = targets.flatMap((t) => findingsOf(t.latest).map((f) => ({ ...f, domain: t.latest.domain })));
    const counts = severityCounts(latestFindings);
    const avg = targets.length ? Math.round(targets.reduce((a, t) => a + t.latest.score, 0) / targets.length) : 0;

    const issueMap = new Map();
    latestFindings.filter((f) => f.severity !== 'info').forEach((f) => {
      const key = titleOf(f).replace(/'[^']*'/g, '…');
      const e = issueMap.get(key) || { title: key, severity: f.severity, domains: new Set() };
      e.domains.add(f.domain);
      issueMap.set(key, e);
    });
    const topIssues = [...issueMap.values()].sort((a, b) => b.domains.size - a.domains.size).slice(0, 8);

    const certs = targets
      .map((t) => ({ domain: t.latest.domain, id: t.latest.id, days: t.latest.details?.https?.days_left }))
      .filter((c) => c.days != null)
      .sort((a, b) => a.days - b.days)
      .slice(0, 6);

    return { targets, counts, avg, topIssues, certs, total: latestFindings.length };
  }, [scans]);

  if (error) return <ErrorBox>{error}</ErrorBox>;
  if (!data) return <Spinner label="Loading…" />;
  if (!scans.length) {
    return (
      <div>
        <PageHeader title="Dashboard" />
        <Card><Empty icon={Activity} title="No data yet"><Link to="/" className="text-accent">Run a scan</Link> to populate the dashboard.</Empty></Card>
      </div>
    );
  }

  const r = risk(data.avg);
  const highPlus = data.counts.critical + data.counts.high;

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="Dashboard" subtitle="Security posture across all scanned targets (latest scan per target)" />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={Globe} label="Targets" value={data.targets.length} sub={`${scans.length} scans total`} />
        <Stat icon={Gauge} label="Average score" value={data.avg} sub={r.label} color={r.hex} />
        <Stat icon={ShieldAlert} label="Open findings" value={data.total} sub="across latest scans" />
        <Stat icon={TriangleAlert} label="High / critical" value={highPlus} sub={highPlus ? 'need attention' : 'none — nice'} color={highPlus ? '#f87171' : '#22d3a6'} />
      </div>

      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between text-sm">
          <span className="font-medium">Findings by severity</span>
          <span className="text-xs text-muted">{data.total} total</span>
        </div>
        <div className="flex h-3 overflow-hidden rounded-full bg-[#1e2631]">
          {SEVERITIES.map((s) => data.counts[s] > 0 && (
            <div key={s} title={`${data.counts[s]} ${s}`} style={{ width: `${(data.counts[s] / Math.max(1, data.total)) * 100}%`, background: SEV_STYLE[s].hex }} />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-4 text-xs">
          {SEVERITIES.map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-muted">
              <span className={`h-2 w-2 rounded-full ${SEV_STYLE[s].dot}`} /> <span className="capitalize">{s}</span> <b className="text-text">{data.counts[s]}</b>
            </span>
          ))}
        </div>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader title="Targets" icon={Globe} subtitle="Latest score and change since previous scan" />
          <div className="divide-y divide-line">
            {data.targets.map(({ latest, prev, count }) => {
              const rr = risk(latest.score);
              const delta = prev ? latest.score - prev.score : null;
              return (
                <Link key={latest.domain} to={`/scans/${latest.id}`} className="flex items-center gap-3 px-5 py-3 transition hover:bg-panel2">
                  <ScoreBadge score={latest.score} color={rr.hex} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-sm">{latest.domain}</div>
                    <div className="text-xs text-muted">{count} scan{count > 1 ? 's' : ''} · {timeAgo(latest.date)}</div>
                  </div>
                  {delta != null && delta !== 0 && (
                    <span className={`font-mono text-xs ${delta > 0 ? 'text-emerald-300' : 'text-red-300'}`}>{delta > 0 ? '▲' : '▼'} {Math.abs(delta)}</span>
                  )}
                  <span className={`w-16 text-right text-xs ${rr.text}`}>{rr.label}</span>
                </Link>
              );
            })}
          </div>
        </Card>

        <div className="flex flex-col gap-6">
          <Card>
            <CardHeader title="Most common issues" icon={ShieldAlert} />
            {data.topIssues.length === 0 ? <p className="px-5 py-6 text-sm text-muted">No open issues.</p> : (
              <div className="divide-y divide-line/60 px-5">
                {data.topIssues.map((i) => (
                  <div key={i.title} className="flex items-center gap-3 py-2.5">
                    <span className={`h-2 w-2 shrink-0 rounded-full ${SEV_STYLE[i.severity].dot}`} />
                    <span className="flex-1 truncate text-sm">{i.title}</span>
                    <span className="text-xs text-muted">{i.domains.size} target{i.domains.size > 1 ? 's' : ''}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card>
            <CardHeader title="Certificate expiry" icon={Lock} />
            {data.certs.length === 0 ? <p className="px-5 py-6 text-sm text-muted">No certificate data.</p> : (
              <div className="divide-y divide-line/60 px-5">
                {data.certs.map((c) => (
                  <Link key={c.domain} to={`/scans/${c.id}`} className="flex items-center justify-between py-2.5 text-sm hover:text-accent">
                    <span className="truncate font-mono text-[13px]">{c.domain}</span>
                    <span className={`font-mono text-xs ${c.days < 0 ? 'text-red-300' : c.days < 21 ? 'text-amber-300' : 'text-muted'}`}>
                      {c.days < 0 ? `expired ${-c.days}d ago` : `${c.days} days`}
                    </span>
                  </Link>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
