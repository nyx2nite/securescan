import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {
  ChevronRight, Clock, Cookie, Download, FileJson, FileWarning, Fingerprint, Globe, ListTree, Lock, Mail, Network,
  RefreshCw, Server, ShieldAlert, ShieldCheck, Trash2,
} from 'lucide-react';
import { api, downloadJson, downloadPdfReport } from '../lib/api';
import { CATEGORY_LABELS, LEGACY_MAX, SEVERITIES, SEV_STYLE, findingsOf, fmtDate, risk, severityCounts, titleOf } from '../lib/util';
import {
  Button, Card, CopyButton, DnsRecords, Empty, ErrorBox, KV, Pill, ScoreRing, SeverityBadge, Spinner, Tabs,
} from '../components/ui';

export default function ScanDetails() {
  const { id } = useParams();
  return <ScanView key={id} id={id} />; // key resets all state when navigating between scans
}

function ScanView({ id }) {
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState('');
  const [tab, setTab] = useState('findings');
  const [busy, setBusy] = useState('');

  useEffect(() => {
    api(`/scans/${id}`).then(setScan).catch((e) => setError(e.message));
  }, [id]);

  const findings = useMemo(() => findingsOf(scan), [scan]);

  if (error) return <div className="flex flex-col gap-4"><ErrorBox>{error}</ErrorBox><Link to="/history" className="text-sm text-accent">← Back to history</Link></div>;
  if (!scan) return <Spinner label="Loading scan…" />;

  const d = scan.details || {};
  const r = risk(scan.score);
  const counts = severityCounts(findings);
  const maxScores = d.max_scores || LEGACY_MAX;
  const ports = Object.values(d.ports || {}).sort((a, b) => a.port - b.port);
  const openPorts = ports.filter((p) => p.status === 'open');

  const run = async (name, fn) => {
    setBusy(name);
    try { await fn(); } catch (e) { setError(e.message); } finally { setBusy(''); }
  };

  const rescan = () => run('rescan', async () => {
    const res = await api('/scans', { method: 'POST', body: { domain: scan.domain, profile: d.profile || 'full' } });
    navigate(`/scans/${res.id}`);
  });
  const remove = () => {
    if (!confirm(`Delete scan of ${scan.domain}?`)) return;
    run('delete', async () => { await api(`/scans/${scan.id}`, { method: 'DELETE' }); navigate('/history'); });
  };

  const tabs = [
    { id: 'findings', label: 'Findings', icon: ShieldAlert, count: findings.length },
    { id: 'tls', label: 'TLS', icon: Lock },
    { id: 'ports', label: 'Ports', icon: Network, count: openPorts.length },
    { id: 'headers', label: 'Headers', icon: Server },
    { id: 'cookies', label: 'Cookies', icon: Cookie, count: d.cookies?.count ?? 0 },
    { id: 'exposure', label: 'Exposure', icon: FileWarning, count: d.exposure ? d.exposure.filter((e) => e.severity !== 'info').length : undefined },
    { id: 'dns', label: 'DNS & Email', icon: Mail },
    { id: 'tech', label: 'Tech', icon: Fingerprint, count: d.technologies?.length },
    { id: 'raw', label: 'Raw', icon: ListTree },
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-1.5 text-xs text-muted">
        <Link to="/history" className="hover:text-text">History</Link>
        <ChevronRight size={13} />
        <span className="font-mono text-text">{scan.domain}</span>
      </div>

      <Card className="p-6">
        <div className="flex flex-wrap items-center gap-8">
          <ScoreRing score={scan.score} color={r.hex} size={128} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="truncate font-mono text-2xl font-semibold">{scan.domain}</h1>
              <span className={`rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ${r.text}`} style={{ background: `${r.hex}1a`, '--tw-ring-color': `${r.hex}55` }}>
                {r.label}
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm text-muted">
              <span className="flex items-center gap-1.5"><Globe size={14} /> <span className="font-mono">{scan.ip}</span></span>
              <span className="flex items-center gap-1.5"><Clock size={14} /> {fmtDate(scan.date)}</span>
              {d.duration_ms != null && <span>Took {(d.duration_ms / 1000).toFixed(1)} s</span>}
              {d.profile && <span className="capitalize">{d.profile} profile</span>}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {SEVERITIES.map((s) => counts[s] > 0 && (
                <span key={s} className={`rounded-md px-2.5 py-1 text-xs ring-1 ${SEV_STYLE[s].bg} ${SEV_STYLE[s].text} ${SEV_STYLE[s].ring}`}>
                  <b>{counts[s]}</b> {s}
                </span>
              ))}
              {findings.length === 0 && <span className="text-xs text-emerald-300">No issues found</span>}
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <Button variant="primary" icon={Download} loading={busy === 'pdf'} onClick={() => run('pdf', () => downloadPdfReport(scan))}>PDF report</Button>
            <div className="flex gap-2">
              <Button icon={FileJson} onClick={() => downloadJson(scan, `securescan-${scan.domain}-${scan.id}.json`)}>JSON</Button>
              <Button icon={RefreshCw} loading={busy === 'rescan'} onClick={rescan}>Rescan</Button>
              <Button variant="danger" icon={Trash2} loading={busy === 'delete'} onClick={remove} title="Delete" />
            </div>
          </div>
        </div>

        <div className="mt-6 grid grid-cols-2 gap-x-8 gap-y-3 border-t border-line pt-5 md:grid-cols-3">
          {Object.entries(maxScores).filter(([k]) => k in (scan.breakdown || {})).map(([k, max]) => {
            const v = scan.breakdown[k];
            const pct = (v / max) * 100;
            const col = pct >= 90 ? '#22d3a6' : pct >= 60 ? '#38bdf8' : pct >= 40 ? '#fbbf24' : '#f87171';
            return (
              <div key={k}>
                <div className="mb-1 flex justify-between text-xs">
                  <span className="text-muted">{CATEGORY_LABELS[k] || k}</span>
                  <span className="font-mono">{v}/{max}</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-[#1e2631]">
                  <div className="h-full rounded-full" style={{ width: `${pct}%`, background: col }} />
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <Card>
        <div className="px-3"><Tabs tabs={tabs} value={tab} onChange={setTab} /></div>
        <div className="p-5">
          {tab === 'findings' && <Findings findings={findings} />}
          {tab === 'tls' && <TlsTab tls={d.https || {}} redirect={d.redirect} />}
          {tab === 'ports' && <PortsTab ports={ports} />}
          {tab === 'headers' && <HeadersTab headers={d.headers || {}} raw={d.raw_headers} />}
          {tab === 'cookies' && <CookiesTab cookies={d.cookies?.cookies || []} />}
          {tab === 'exposure' && <ExposureTab exposure={d.exposure} methods={d.methods} />}
          {tab === 'dns' && <DnsTab dns={d.dns} email={d.email} />}
          {tab === 'tech' && <TechTab tech={d.technologies} />}
          {tab === 'raw' && (
            <div className="relative">
              <CopyButton text={JSON.stringify(scan, null, 2)} className="absolute right-2 top-2" />
              <pre className="max-h-[560px] overflow-auto rounded-lg bg-bg p-4 font-mono text-xs text-muted">{JSON.stringify(scan, null, 2)}</pre>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

const NotAvailable = () => <Empty icon={ListTree} title="Not available for this scan">Rescan the target to collect this data.</Empty>;

function Findings({ findings }) {
  const [filter, setFilter] = useState('all');
  const [open, setOpen] = useState(null);
  if (!findings.length) return <Empty icon={ShieldCheck} title="No findings">This target passed every check.</Empty>;
  const shown = filter === 'all' ? findings : findings.filter((f) => f.severity === filter);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex gap-1.5">
        {['all', ...SEVERITIES.filter((s) => findings.some((f) => f.severity === s))].map((s) => (
          <button key={s} onClick={() => setFilter(s)}
            className={`rounded-md px-2.5 py-1 text-xs capitalize ring-1 cursor-pointer ${filter === s ? 'bg-accent/10 text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}>
            {s}
          </button>
        ))}
      </div>
      <div className="divide-y divide-line overflow-hidden rounded-lg border border-line">
        {shown.map((f, i) => {
          const isOpen = open === i;
          const det = f.details || {};
          const extra = Object.entries(det).filter(([k]) => !['title', 'remediation', 'category'].includes(k));
          return (
            <div key={i} className="bg-bg/40">
              <button onClick={() => setOpen(isOpen ? null : i)} className="flex w-full items-center gap-3 px-4 py-3 text-left transition hover:bg-panel2 cursor-pointer">
                <SeverityBadge severity={f.severity} />
                <span className="flex-1 text-sm font-medium">{titleOf(f)}</span>
                {det.category && <span className="text-xs text-muted">{CATEGORY_LABELS[det.category === 'exposure' ? 'config' : det.category] || det.category}</span>}
                <ChevronRight size={15} className={`text-muted transition ${isOpen ? 'rotate-90' : ''}`} />
              </button>
              {isOpen && (
                <div className="space-y-3 px-4 pb-4 pl-[1.1rem] text-sm">
                  <p className="text-muted">{f.description}</p>
                  {det.remediation && (
                    <div className="rounded-lg border border-accent/25 bg-accent/5 p-3">
                      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-accent">Remediation</div>
                      <div>{det.remediation}</div>
                    </div>
                  )}
                  {extra.length > 0 && (
                    <pre className="overflow-auto rounded-lg bg-bg p-3 font-mono text-xs text-muted">{JSON.stringify(Object.fromEntries(extra), null, 2)}</pre>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TlsTab({ tls, redirect }) {
  const issuer = tls.issuer || {};
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <div>
        <KV label="HTTPS"><Pill ok={tls.enabled}>{tls.enabled ? 'Enabled' : 'Unavailable'}</Pill></KV>
        <KV label="Certificate"><Pill ok={tls.certificate_valid}>{tls.certificate_valid ? 'Trusted' : 'Invalid'}</Pill></KV>
        {tls.error && <KV label="Error" mono>{tls.error}</KV>}
        <KV label="Protocol" mono>{tls.protocol || '—'}</KV>
        <KV label="Cipher" mono>{tls.cipher || '—'}</KV>
        <KV label="Legacy TLS 1.0/1.1">
          {tls.legacy_protocols == null ? '—' : tls.legacy_protocols.length ? <Pill ok={false}>{tls.legacy_protocols.join(', ')}</Pill> : <Pill ok>Rejected</Pill>}
        </KV>
        <KV label="HTTP → HTTPS redirect">
          {redirect?.redirects_to_https == null ? '—' : <Pill ok={redirect.redirects_to_https}>{redirect.redirects_to_https ? 'Yes' : 'No'}</Pill>}
        </KV>
      </div>
      <div>
        <KV label="Subject" mono>{tls.subject || '—'}</KV>
        <KV label="Issuer">{issuer.organizationName || issuer.commonName || '—'}</KV>
        <KV label="Valid from" mono>{tls.valid_from || '—'}</KV>
        <KV label="Expires" mono>{tls.expiry || '—'}</KV>
        <KV label="Days left">
          {tls.days_left == null ? '—' : <span className={tls.days_left < 21 ? 'text-red-300' : 'text-emerald-300'}>{tls.days_left}</span>}
        </KV>
        <KV label="Self-signed">{tls.self_signed == null ? '—' : tls.self_signed ? 'Yes' : 'No'}</KV>
        {tls.san?.length > 0 && (
          <div className="pt-3">
            <div className="mb-2 text-sm text-muted">Subject Alternative Names ({tls.san.length})</div>
            <div className="flex flex-wrap gap-1.5">
              {tls.san.map((s) => <span key={s} className="rounded bg-panel2 px-2 py-0.5 font-mono text-xs">{s}</span>)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function PortsTab({ ports }) {
  const [showClosed, setShowClosed] = useState(false);
  if (!ports.length) return <NotAvailable />;
  const list = showClosed ? ports : ports.filter((p) => p.status === 'open');
  return (
    <div className="flex flex-col gap-3">
      <label className="flex items-center gap-2 text-xs text-muted">
        <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Show closed ports ({ports.length} scanned)
      </label>
      {list.length === 0 ? <Empty icon={Network} title="No open ports detected" /> : (
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-muted">
            <tr className="border-b border-line"><th className="py-2 font-medium">Port</th><th className="font-medium">Service</th><th className="font-medium">State</th><th className="font-medium">Banner</th></tr>
          </thead>
          <tbody>
            {list.map((p) => (
              <tr key={p.port} className="border-b border-line/60 last:border-0">
                <td className="py-2.5 font-mono">{p.port}/tcp</td>
                <td>{p.service}</td>
                <td><span className={p.status === 'open' ? 'text-emerald-300' : 'text-muted'}>{p.status}</span></td>
                <td className="max-w-md truncate font-mono text-xs text-muted" title={p.banner}>{p.banner || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function HeadersTab({ headers, raw }) {
  return (
    <div className="flex flex-col gap-6">
      <div className="divide-y divide-line/60">
        {Object.entries(headers).map(([name, h]) => (
          <div key={name} className="flex items-start gap-4 py-2.5">
            <span className="w-48 shrink-0 text-sm">{name}</span>
            <Pill ok={h.present}>{h.present ? 'Present' : 'Missing'}</Pill>
            <span className="min-w-0 flex-1 break-all font-mono text-xs text-muted">
              {h.present ? h.value : ''}
              {h.notes?.length > 0 && <span className="mt-1 block text-amber-300">⚠ {h.notes.join('; ')}</span>}
            </span>
          </div>
        ))}
      </div>
      {raw && Object.keys(raw).length > 0 && (
        <div>
          <div className="mb-2 text-sm text-muted">All response headers</div>
          <div className="rounded-lg bg-bg p-3 font-mono text-xs">
            {Object.entries(raw).map(([k, v]) => (
              <div key={k} className="break-all py-0.5"><span className="text-accent">{k}</span>: <span className="text-muted">{v}</span></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CookiesTab({ cookies }) {
  if (!cookies.length) return <Empty icon={Cookie} title="No cookies set" />;
  const Flag = ({ ok }) => <span className={ok ? 'text-emerald-300' : 'text-red-300'}>{ok ? '✓' : '✗'}</span>;
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs text-muted">
        <tr className="border-b border-line"><th className="py-2 font-medium">Name</th><th className="font-medium">Secure</th><th className="font-medium">HttpOnly</th><th className="font-medium">SameSite</th><th className="font-medium">Domain</th></tr>
      </thead>
      <tbody>
        {cookies.map((c, i) => (
          <tr key={i} className="border-b border-line/60 last:border-0">
            <td className="py-2.5 font-mono text-xs">{c.name}</td>
            <td><Flag ok={c.secure} /></td>
            <td><Flag ok={c.httponly} /></td>
            <td className={String(c.samesite).toLowerCase() === 'none' ? 'text-amber-300' : ''}>{String(c.samesite)}</td>
            <td className="font-mono text-xs text-muted">{c.domain || '—'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ExposureTab({ exposure, methods }) {
  if (!exposure) return <NotAvailable />;
  const issues = exposure.filter((e) => e.severity !== 'info');
  const info = exposure.filter((e) => e.severity === 'info');
  const robots = info.find((e) => e.path === '/robots.txt');
  return (
    <div className="flex flex-col gap-6">
      {issues.length === 0 ? (
        <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/5 px-4 py-3 text-sm text-emerald-300">No sensitive files or admin panels found among the probed paths.</div>
      ) : (
        <div className="divide-y divide-line/60">
          {issues.map((e) => (
            <div key={e.path} className="flex items-center gap-3 py-2.5">
              <SeverityBadge severity={e.severity} /><span className="font-mono text-sm">{e.path}</span><span className="text-sm text-muted">{e.title}</span>
            </div>
          ))}
        </div>
      )}
      {methods && (
        <div className="grid gap-x-8 md:grid-cols-2">
          <KV label="Allowed methods" mono>{methods.allow || 'not advertised'}</KV>
          <KV label="TRACE"><Pill ok={!methods.trace_enabled}>{methods.trace_enabled ? 'Enabled' : 'Disabled'}</Pill></KV>
          <KV label="CORS Allow-Origin" mono>{methods.cors?.allow_origin || 'not set'}</KV>
          <KV label="Reflects arbitrary origin"><Pill ok={!methods.cors?.reflects_origin}>{methods.cors?.reflects_origin ? 'Yes' : 'No'}</Pill></KV>
        </div>
      )}
      <div className="flex flex-wrap gap-2 text-xs">
        {info.map((e) => <span key={e.path} className="rounded bg-panel2 px-2 py-1 font-mono text-muted">{e.path} ✓</span>)}
      </div>
      {robots?.disallowed?.length > 0 && (
        <div>
          <div className="mb-2 text-sm text-muted">robots.txt disallowed paths (often reveal interesting endpoints)</div>
          <div className="flex flex-wrap gap-1.5">
            {robots.disallowed.map((p, i) => <span key={i} className="rounded bg-panel2 px-2 py-0.5 font-mono text-xs">{p}</span>)}
          </div>
        </div>
      )}
    </div>
  );
}

function DnsTab({ dns, email }) {
  if (!dns || !Object.keys(dns).length) return <NotAvailable />;
  return (
    <div className="grid gap-6 md:grid-cols-[1fr_1.3fr]">
      <div>
        {email ? (
          <>
            <KV label="Mail server (MX)">{email.has_mx ? 'Yes' : 'No'}</KV>
            <KV label="SPF">{email.spf ? <Pill ok={['-', '~'].includes(email.spf_all)}>{email.spf_all ? `${email.spf_all}all` : 'present'}</Pill> : <Pill ok={!email.has_mx}>Missing</Pill>}</KV>
            <KV label="DMARC">{email.dmarc ? <Pill ok={['quarantine', 'reject'].includes(email.dmarc_policy)}>p={email.dmarc_policy || '?'}</Pill> : <Pill ok={!email.has_mx}>Missing</Pill>}</KV>
            <KV label="CAA"><Pill ok={email.caa}>{email.caa ? 'Present' : 'Missing'}</Pill></KV>
          </>
        ) : <p className="text-sm text-muted">Email checks not applicable.</p>}
      </div>
      <DnsRecords records={dns} />
    </div>
  );
}

function TechTab({ tech }) {
  if (!tech) return <NotAvailable />;
  if (!tech.length) return <Empty icon={Fingerprint} title="No technologies identified" />;
  return (
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {tech.map((t) => (
        <div key={t.name} className="rounded-lg border border-line bg-bg/50 px-4 py-3">
          <div className="text-sm font-medium">{t.name}</div>
          <div className="text-xs text-muted">via {t.source}</div>
        </div>
      ))}
    </div>
  );
}
