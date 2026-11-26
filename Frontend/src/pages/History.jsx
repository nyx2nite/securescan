import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { History as HistoryIcon, Search, Trash2 } from 'lucide-react';
import { api, downloadJson } from '../lib/api';
import { findingsOf, fmtDate, risk, severityCounts, SEV_STYLE } from '../lib/util';
import { Button, Card, Empty, ErrorBox, PageHeader, ScoreBadge, Spinner } from '../components/ui';

const FILTERS = [
  ['all', 'All'],
  ['critical', 'Critical'],
  ['fair', 'Fair'],
  ['good', 'Good'],
  ['excellent', 'Excellent'],
];

export default function History() {
  const [scans, setScans] = useState(null);
  const [error, setError] = useState('');
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState('all');

  const load = () => api('/scans').then(setScans).catch((e) => setError(e.message));
  useEffect(() => { load(); }, []);

  const shown = useMemo(() => (scans || []).filter((s) =>
    (filter === 'all' || risk(s.score).key === filter) &&
    (!q || s.domain.includes(q.toLowerCase()) || s.ip.includes(q))), [scans, q, filter]);

  const del = async (e, s) => {
    e.preventDefault();
    if (!confirm(`Delete scan of ${s.domain}?`)) return;
    await api(`/scans/${s.id}`, { method: 'DELETE' }).catch((err) => setError(err.message));
    setScans((list) => list.filter((x) => x.id !== s.id));
  };

  const clearAll = async () => {
    if (!confirm(`Delete all ${scans.length} scans and their reports? This cannot be undone.`)) return;
    await api('/scans', { method: 'DELETE' }).catch((err) => setError(err.message));
    load();
  };

  return (
    <div>
      <PageHeader
        title="Scan history"
        subtitle={scans ? `${scans.length} scans stored locally` : ' '}
        right={scans?.length > 0 && (
          <div className="flex gap-2">
            <Button onClick={() => downloadJson(scans, 'securescan-history.json')}>Export all (JSON)</Button>
            <Button variant="danger" icon={Trash2} onClick={clearAll}>Clear all</Button>
          </div>
        )}
      />
      <ErrorBox>{error}</ErrorBox>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by domain or IP"
            className="w-full rounded-lg border border-line bg-panel py-2 pl-9 pr-3 text-sm outline-none focus:border-accent/60" />
        </div>
        <div className="flex gap-1.5">
          {FILTERS.map(([id, label]) => (
            <button key={id} onClick={() => setFilter(id)}
              className={`rounded-md px-2.5 py-1 text-xs ring-1 cursor-pointer ${filter === id ? 'bg-accent/10 text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}>
              {label}
            </button>
          ))}
        </div>
      </div>

      <Card>
        {!scans ? <Spinner label="Loading…" /> : shown.length === 0 ? (
          <Empty icon={HistoryIcon} title={scans.length ? 'No matching scans' : 'No scans yet'}>
            {!scans.length && <Link to="/" className="text-accent">Run your first scan →</Link>}
          </Empty>
        ) : (
          <div className="divide-y divide-line">
            {shown.map((s) => {
              const r = risk(s.score);
              const c = severityCounts(findingsOf(s));
              return (
                <Link key={s.id} to={`/scans/${s.id}`} className="group flex items-center gap-4 px-5 py-3.5 transition hover:bg-panel2">
                  <ScoreBadge score={s.score} color={r.hex} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-sm">{s.domain}</div>
                    <div className="text-xs text-muted"><span className="font-mono">{s.ip}</span> · {fmtDate(s.date)}</div>
                  </div>
                  <div className="hidden gap-1.5 md:flex">
                    {['critical', 'high', 'medium', 'low'].map((sev) => c[sev] > 0 && (
                      <span key={sev} className={`rounded px-1.5 py-0.5 text-[11px] ring-1 ${SEV_STYLE[sev].bg} ${SEV_STYLE[sev].text} ${SEV_STYLE[sev].ring}`}>
                        {c[sev]} {sev}
                      </span>
                    ))}
                  </div>
                  <span className={`w-20 text-right text-xs font-medium ${r.text}`}>{r.label}</span>
                  <button onClick={(e) => del(e, s)} title="Delete"
                    className="rounded-md p-1.5 text-muted opacity-0 transition hover:bg-red-500/10 hover:text-red-300 group-hover:opacity-100 cursor-pointer">
                    <Trash2 size={15} />
                  </button>
                </Link>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}
