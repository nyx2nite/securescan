import { useMemo, useState } from 'react';
import { NavLink, useParams } from 'react-router-dom';
import {
  Binary, Dices, FileText, Fingerprint, Globe, Hash, KeyRound, Lock, Mail, Network, Search, Server,
} from 'lucide-react';
import { api } from '../lib/api';
import {
  Button, Card, CardHeader, CopyButton, DnsRecords, Empty, ErrorBox, Input, KV, Pill, TextArea,
} from '../components/ui';

const TOOLS = [
  { group: 'Recon', id: 'dns', label: 'DNS lookup', icon: Globe, el: DnsTool },
  { group: 'Recon', id: 'subdomains', label: 'Subdomain finder', icon: Search, el: SubdomainTool },
  { group: 'Recon', id: 'whois', label: 'WHOIS / RDAP', icon: FileText, el: WhoisTool },
  { group: 'Network', id: 'ports', label: 'Port scanner', icon: Network, el: PortTool },
  { group: 'Network', id: 'tls', label: 'TLS inspector', icon: Lock, el: TlsTool },
  { group: 'Network', id: 'headers', label: 'HTTP headers', icon: Server, el: HeadersTool },
  { group: 'Crypto', id: 'hash', label: 'Hash generator', icon: Hash, el: HashTool },
  { group: 'Crypto', id: 'hashid', label: 'Hash identifier', icon: Fingerprint, el: HashIdTool },
  { group: 'Crypto', id: 'encode', label: 'Encoder / decoder', icon: Binary, el: EncoderTool },
  { group: 'Crypto', id: 'jwt', label: 'JWT decoder', icon: KeyRound, el: JwtTool },
  { group: 'Crypto', id: 'password', label: 'Password tools', icon: Dices, el: PasswordTool },
];

export default function Tools() {
  const { tool = 'dns' } = useParams();
  const current = TOOLS.find((t) => t.id === tool) || TOOLS[0];
  const Tool = current.el;
  const groups = [...new Set(TOOLS.map((t) => t.group))];
  return (
    <div className="grid gap-6 md:grid-cols-[200px_1fr]">
      <nav className="flex flex-col gap-4">
        {groups.map((g) => (
          <div key={g}>
            <div className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-[#5b6777]">{g}</div>
            {TOOLS.filter((t) => t.group === g).map((t) => (
              <NavLink key={t.id} to={`/tools/${t.id}`}
                className={() => `flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-sm transition ${t.id === current.id ? 'bg-accent/10 text-accent' : 'text-muted hover:bg-panel2 hover:text-text'}`}>
                <t.icon size={15} /> {t.label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <Card className="min-w-0 self-start">
        <CardHeader title={current.label} icon={current.icon} />
        <div className="p-5"><Tool key={current.id} /></div>
      </Card>
    </div>
  );
}

// ── helpers ───────────────────────────────────────────────────
function useRequest() {
  const [state, setState] = useState({ loading: false, error: '', data: null });
  const run = async (fn) => {
    setState({ loading: true, error: '', data: null });
    try { setState({ loading: false, error: '', data: await fn() }); } catch (e) { setState({ loading: false, error: e.message, data: null }); }
  };
  return [state, run];
}

function QueryForm({ placeholder, onSubmit, loading, button = 'Run', children, defaultValue = '' }) {
  const [v, setV] = useState(defaultValue);
  return (
    <form className="flex flex-wrap gap-3" onSubmit={(e) => { e.preventDefault(); if (v.trim()) onSubmit(v.trim()); }}>
      <Input mono autoFocus value={v} onChange={(e) => setV(e.target.value)} placeholder={placeholder} className="min-w-64 flex-1" />
      {children}
      <Button type="submit" variant="primary" loading={loading}>{button}</Button>
    </form>
  );
}

const Out = ({ children }) => <div className="mt-5 flex flex-col gap-4">{children}</div>;
const qs = (o) => new URLSearchParams(o).toString();

// ── Recon ─────────────────────────────────────────────────────
function DnsTool() {
  const [s, run] = useRequest();
  return (
    <>
      <QueryForm placeholder="example.com" loading={s.loading} button="Lookup" onSubmit={(d) => run(() => api(`/tools/dns?${qs({ domain: d })}`))} />
      <ErrorBox>{s.error}</ErrorBox>
      {s.data && (
        <Out>
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="flex items-center gap-1.5 text-muted"><Mail size={13} /> Email security:</span>
            <Pill ok={!!s.data.email.spf}>SPF {s.data.email.spf_all ? `${s.data.email.spf_all}all` : s.data.email.spf ? '' : 'missing'}</Pill>
            <Pill ok={['quarantine', 'reject'].includes(s.data.email.dmarc_policy)}>DMARC {s.data.email.dmarc_policy || 'missing'}</Pill>
            <Pill ok={s.data.email.caa}>CAA {s.data.email.caa ? '' : 'missing'}</Pill>
          </div>
          {Object.values(s.data.records).some((v) => v?.length) ? <DnsRecords records={s.data.records} /> : <Empty title="No records found" />}
        </Out>
      )}
    </>
  );
}

function SubdomainTool() {
  const [s, run] = useRequest();
  const [filter, setFilter] = useState('');
  const list = (s.data?.subdomains || []).filter((x) => x.name.includes(filter));
  return (
    <>
      <p className="mb-4 text-sm text-muted">Passive enumeration via Certificate Transparency logs (crt.sh). Nothing is sent to the target itself.</p>
      <QueryForm placeholder="example.com" loading={s.loading} button="Enumerate" onSubmit={(d) => run(() => api(`/tools/subdomains?${qs({ domain: d })}`))} />
      <ErrorBox>{s.error}</ErrorBox>
      {s.loading && <p className="mt-4 text-sm text-muted">Querying CT logs — this can take 10–20 seconds…</p>}
      {s.data && (
        <Out>
          <div className="flex items-center gap-3">
            <span className="text-sm text-muted">{s.data.count} unique names · {s.data.subdomains.filter((x) => x.ip).length} resolve</span>
            <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter…" className="ml-auto max-w-56 py-1.5" />
            <CopyButton text={list.map((x) => x.name).join('\n')} />
          </div>
          <div className="max-h-[480px] overflow-auto rounded-lg border border-line">
            {list.map((x) => (
              <div key={x.name} className="flex justify-between border-b border-line/60 px-4 py-1.5 font-mono text-xs last:border-0">
                <span>{x.name}</span><span className={x.ip ? 'text-accent' : 'text-[#5b6777]'}>{x.ip || 'no A record'}</span>
              </div>
            ))}
          </div>
        </Out>
      )}
    </>
  );
}

function WhoisTool() {
  const [s, run] = useRequest();
  const [now] = useState(() => Date.now());
  const d = s.data;
  const days = d?.expires ? Math.round((new Date(d.expires) - now) / 864e5) : null;
  return (
    <>
      <QueryForm placeholder="example.com" loading={s.loading} button="Lookup" onSubmit={(v) => run(() => api(`/tools/whois?${qs({ domain: v })}`))} />
      <ErrorBox>{s.error}</ErrorBox>
      {d && (
        <Out>
          <div>
            <KV label="Domain" mono>{d.domain}</KV>
            <KV label="Registrar">{d.registrar || '—'}</KV>
            <KV label="Created" mono>{d.created?.slice(0, 10) || '—'}</KV>
            <KV label="Updated" mono>{d.updated?.slice(0, 10) || '—'}</KV>
            <KV label="Expires" mono>{d.expires ? `${d.expires.slice(0, 10)} (${days} days)` : '—'}</KV>
            <KV label="DNSSEC">{d.dnssec == null ? '—' : <Pill ok={d.dnssec}>{d.dnssec ? 'Signed' : 'Unsigned'}</Pill>}</KV>
            <KV label="Nameservers" mono>{d.nameservers.join(', ') || '—'}</KV>
            <KV label="Status" mono>{d.status.join(', ') || '—'}</KV>
          </div>
        </Out>
      )}
    </>
  );
}

// ── Network ───────────────────────────────────────────────────
function PortTool() {
  const [s, run] = useRequest();
  const [ports, setPorts] = useState('common');
  const presets = [['common', 'Common (35)'], ['1-1024', 'Well-known 1-1024'], ['1-2048', '1-2048'], ['80,443,8000,8080,8443,3000,5000', 'Web']];
  return (
    <>
      <QueryForm placeholder="host or IP, e.g. scanme.nmap.org" loading={s.loading} button="Scan"
        onSubmit={(h) => run(() => api('/tools/ports', { method: 'POST', body: { host: h, ports } }))}>
        <Input mono value={ports} onChange={(e) => setPorts(e.target.value)} className="w-56" placeholder="22,80,443 or 1-1024" />
      </QueryForm>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {presets.map(([v, l]) => (
          <button key={v} onClick={() => setPorts(v)} className={`rounded-md px-2 py-0.5 text-xs ring-1 cursor-pointer ${ports === v ? 'text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}>{l}</button>
        ))}
      </div>
      <ErrorBox>{s.error}</ErrorBox>
      {s.data && (
        <Out>
          <p className="text-sm text-muted"><span className="font-mono text-text">{s.data.host}</span> ({s.data.ip}) — {s.data.open.length} open of {s.data.scanned} scanned</p>
          {s.data.open.length === 0 ? <Empty icon={Network} title="No open ports" /> : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted"><tr className="border-b border-line"><th className="py-2 font-medium">Port</th><th className="font-medium">Service</th><th className="font-medium">Banner</th></tr></thead>
              <tbody>
                {s.data.open.map((p) => (
                  <tr key={p.port} className="border-b border-line/60 last:border-0">
                    <td className="py-2 font-mono text-emerald-300">{p.port}/tcp</td><td>{p.service}</td>
                    <td className="max-w-md truncate font-mono text-xs text-muted" title={p.banner}>{p.banner || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Out>
      )}
    </>
  );
}

function TlsTool() {
  const [s, run] = useRequest();
  const [port, setPort] = useState('443');
  const t = s.data;
  return (
    <>
      <QueryForm placeholder="example.com" loading={s.loading} button="Inspect" onSubmit={(h) => run(() => api(`/tools/tls?${qs({ host: h, port })}`))}>
        <Input mono value={port} onChange={(e) => setPort(e.target.value)} className="w-24" />
      </QueryForm>
      <ErrorBox>{s.error}</ErrorBox>
      {t && (
        <Out>
          <div>
            <KV label="Handshake"><Pill ok={t.enabled}>{t.enabled ? 'OK' : 'Failed'}</Pill></KV>
            <KV label="Certificate"><Pill ok={t.certificate_valid}>{t.certificate_valid ? 'Trusted' : 'Not trusted'}</Pill></KV>
            {t.error && <KV label="Error" mono>{t.error}</KV>}
            <KV label="Protocol / cipher" mono>{t.protocol ? `${t.protocol} · ${t.cipher}` : '—'}</KV>
            <KV label="Subject" mono>{t.subject || '—'}</KV>
            <KV label="Issuer">{t.issuer?.organizationName || t.issuer?.commonName || '—'}</KV>
            <KV label="Validity" mono>{t.valid_from ? `${t.valid_from} → ${t.expiry}` : '—'}</KV>
            <KV label="Days left">{t.days_left ?? '—'}</KV>
            <KV label="Legacy TLS 1.0/1.1">{t.legacy_protocols?.length ? <Pill ok={false}>{t.legacy_protocols.join(', ')}</Pill> : <Pill ok>Rejected</Pill>}</KV>
            <KV label="SANs" mono>{t.san?.join(', ') || '—'}</KV>
          </div>
        </Out>
      )}
    </>
  );
}

function HeadersTool() {
  const [s, run] = useRequest();
  const [method, setMethod] = useState('GET');
  return (
    <>
      <QueryForm placeholder="https://example.com/path" loading={s.loading} button="Fetch" onSubmit={(u) => run(() => api(`/tools/headers?${qs({ url: u, method })}`))}>
        <select value={method} onChange={(e) => setMethod(e.target.value)} className="rounded-lg border border-line bg-bg px-3 text-sm">
          {['GET', 'HEAD', 'OPTIONS'].map((m) => <option key={m}>{m}</option>)}
        </select>
      </QueryForm>
      <ErrorBox>{s.error}</ErrorBox>
      {s.data && (
        <Out>
          <div className="flex flex-col gap-1 text-xs">
            {s.data.redirects.map((r, i) => (
              <div key={i} className="flex gap-3 font-mono">
                <span className={r.status < 300 ? 'text-emerald-300' : r.status < 400 ? 'text-amber-300' : 'text-red-300'}>{r.status}</span>
                <span className="break-all text-muted">{r.url}</span>
              </div>
            ))}
            <span className="mt-1 text-muted">{s.data.elapsed_ms} ms</span>
          </div>
          <div className="relative rounded-lg bg-bg p-3 font-mono text-xs">
            <CopyButton className="absolute right-2 top-2" text={Object.entries(s.data.headers).map(([k, v]) => `${k}: ${v}`).join('\n')} />
            {Object.entries(s.data.headers).map(([k, v]) => (
              <div key={k} className="break-all py-0.5"><span className="text-accent">{k}</span>: <span className="text-muted">{v}</span></div>
            ))}
          </div>
        </Out>
      )}
    </>
  );
}

// ── Crypto ────────────────────────────────────────────────────
function HashTool() {
  const [text, setText] = useState('');
  const [s, run] = useRequest();
  return (
    <>
      <TextArea rows={4} value={text} onChange={(e) => setText(e.target.value)} placeholder="Text to hash (UTF-8)" />
      <div className="mt-3"><Button variant="primary" loading={s.loading} onClick={() => run(() => api('/tools/hash', { method: 'POST', body: { text } }))}>Hash</Button></div>
      <ErrorBox>{s.error}</ErrorBox>
      {s.data && (
        <Out>
          {Object.entries(s.data).map(([alg, h]) => (
            <div key={alg} className="flex items-center gap-3">
              <span className="w-20 shrink-0 text-xs uppercase text-muted">{alg.replace('_', '-')}</span>
              <span className="min-w-0 flex-1 break-all font-mono text-xs">{h}</span>
              <CopyButton text={h} />
            </div>
          ))}
        </Out>
      )}
    </>
  );
}

const HASH_PATTERNS = [
  [/^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$/, 'bcrypt'],
  [/^\$argon2(id|i|d)\$/, 'Argon2'],
  [/^\$6\$/, 'SHA-512 crypt (Linux shadow)'],
  [/^\$5\$/, 'SHA-256 crypt'],
  [/^\$1\$/, 'MD5 crypt'],
  [/^\$apr1\$/, 'Apache APR1-MD5'],
  [/^\$y\$/, 'yescrypt (Linux shadow)'],
  [/^pbkdf2_sha256\$/, 'Django PBKDF2-SHA256'],
  [/^\{SSHA\}/, 'LDAP Salted SHA-1'],
  [/^[a-f0-9]{32}$/i, 'MD5, NTLM, MD4'],
  [/^[a-f0-9]{40}$/i, 'SHA-1, RIPEMD-160'],
  [/^[a-f0-9]{56}$/i, 'SHA-224, SHA3-224'],
  [/^[a-f0-9]{64}$/i, 'SHA-256, SHA3-256, BLAKE2s'],
  [/^[a-f0-9]{96}$/i, 'SHA-384, SHA3-384'],
  [/^[a-f0-9]{128}$/i, 'SHA-512, SHA3-512, BLAKE2b, Whirlpool'],
  [/^[a-f0-9]{16}$/i, 'MySQL323, CRC-64, half MD5'],
  [/^\*[A-F0-9]{40}$/, 'MySQL 4.1+ (SHA1(SHA1))'],
  [/^[a-f0-9]{8}$/i, 'CRC-32, Adler-32'],
];

function HashIdTool() {
  const [h, setH] = useState('');
  const v = h.trim();
  const matches = v ? HASH_PATTERNS.filter(([re]) => re.test(v)).map(([, n]) => n) : [];
  return (
    <>
      <Input mono value={h} onChange={(e) => setH(e.target.value)} placeholder="Paste a hash, e.g. 5f4dcc3b5aa765d61d8327deb882cf99" />
      {v && (
        <Out>
          {matches.length ? matches.map((m) => <div key={m} className="rounded-lg border border-line bg-bg px-4 py-2.5 text-sm">{m}</div>)
            : <p className="text-sm text-muted">Unknown format ({v.length} chars).</p>}
        </Out>
      )}
    </>
  );
}

const utf8ToB64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
const b64ToUtf8 = (s) => new TextDecoder().decode(Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0)));
const CODECS = {
  'Base64': [utf8ToB64, b64ToUtf8],
  'Base64URL': [(s) => utf8ToB64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''), b64ToUtf8],
  'URL': [encodeURIComponent, decodeURIComponent],
  'Hex': [(s) => [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, '0')).join(''),
    (s) => new TextDecoder().decode(Uint8Array.from(s.replace(/[^0-9a-f]/gi, '').match(/../g) || [], (x) => parseInt(x, 16)))],
  'HTML entities': [(s) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`),
    (s) => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; }],
  'Binary': [(s) => [...new TextEncoder().encode(s)].map((b) => b.toString(2).padStart(8, '0')).join(' '),
    (s) => new TextDecoder().decode(Uint8Array.from(s.trim().split(/\s+/), (b) => parseInt(b, 2)))],
  'ROT13': [(s) => s.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)), null],
};

function EncoderTool() {
  const [input, setInput] = useState('');
  const [codec, setCodec] = useState('Base64');
  const [mode, setMode] = useState('encode');
  const out = useMemo(() => {
    if (!input) return { value: '' };
    try {
      const [enc, dec] = CODECS[codec];
      return { value: (mode === 'encode' || !dec ? enc : dec)(input) };
    } catch (e) { return { error: `Cannot ${mode}: ${e.message}` }; }
  }, [input, codec, mode]);
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5">
        {Object.keys(CODECS).map((c) => (
          <button key={c} onClick={() => setCodec(c)} className={`rounded-md px-2.5 py-1 text-xs ring-1 cursor-pointer ${codec === c ? 'bg-accent/10 text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}>{c}</button>
        ))}
        <div className="ml-auto flex gap-1.5">
          {['encode', 'decode'].map((m) => (
            <button key={m} onClick={() => setMode(m)} className={`rounded-md px-2.5 py-1 text-xs capitalize ring-1 cursor-pointer ${mode === m ? 'bg-accent/10 text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}>{m}</button>
          ))}
        </div>
      </div>
      <TextArea rows={6} value={input} onChange={(e) => setInput(e.target.value)} placeholder="Input" />
      <div className="relative">
        <TextArea rows={6} readOnly value={out.error || out.value} className={out.error ? 'text-red-300' : ''} placeholder="Output" />
        {out.value && <CopyButton text={out.value} className="absolute right-2 top-2" />}
      </div>
    </div>
  );
}

function JwtTool() {
  const [token, setToken] = useState('');
  const [now] = useState(() => Date.now());
  const parsed = useMemo(() => {
    const t = token.trim();
    if (!t) return null;
    const parts = t.split('.');
    if (parts.length < 2) return { error: 'Not a JWT (expected header.payload.signature)' };
    try {
      return { header: JSON.parse(b64ToUtf8(parts[0])), payload: JSON.parse(b64ToUtf8(parts[1])), signed: !!parts[2] };
    } catch (e) { return { error: `Decode failed: ${e.message}` }; }
  }, [token]);
  const p = parsed?.payload || {};
  const warn = [];
  if (parsed?.header) {
    if (String(parsed.header.alg).toLowerCase() === 'none' || !parsed.signed) warn.push("Unsigned token (alg 'none') — must be rejected by servers.");
    if (/^HS/.test(parsed.header.alg)) warn.push('HMAC-signed: secret may be brute-forceable if weak.');
    if (p.exp && p.exp * 1000 < now) warn.push('Token is expired.');
    if (!p.exp) warn.push('No expiry (exp) claim.');
  }
  const ts = (v) => (v ? `${v} — ${new Date(v * 1000).toLocaleString()}` : '—');
  return (
    <div className="flex flex-col gap-4">
      <TextArea rows={4} value={token} onChange={(e) => setToken(e.target.value)} placeholder="eyJhbGciOi…" />
      <p className="text-xs text-muted">Decoded locally — the token never leaves this app.</p>
      {parsed?.error && <ErrorBox>{parsed.error}</ErrorBox>}
      {parsed?.header && (
        <>
          {warn.map((w) => <div key={w} className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">{w}</div>)}
          <div className="grid gap-4 md:grid-cols-2">
            <div><div className="mb-1 text-xs text-muted">Header</div><pre className="overflow-auto rounded-lg bg-bg p-3 font-mono text-xs text-sky-300">{JSON.stringify(parsed.header, null, 2)}</pre></div>
            <div><div className="mb-1 text-xs text-muted">Payload</div><pre className="overflow-auto rounded-lg bg-bg p-3 font-mono text-xs text-accent">{JSON.stringify(p, null, 2)}</pre></div>
          </div>
          <div>
            <KV label="Issued at (iat)" mono>{ts(p.iat)}</KV>
            <KV label="Not before (nbf)" mono>{ts(p.nbf)}</KV>
            <KV label="Expires (exp)" mono>{ts(p.exp)}</KV>
          </div>
        </>
      )}
    </div>
  );
}

const COMMON = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'iloveyou', 'monkey', 'dragon', 'abc123', '111111', 'football'];

function strength(pw) {
  if (!pw) return null;
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let bits = pw.length * Math.log2(Math.max(pool, 1));
  const issues = [];
  if (COMMON.some((c) => pw.toLowerCase().includes(c))) { bits = Math.min(bits, 10); issues.push('Contains a very common password'); }
  if (/(.)\1{2,}/.test(pw)) { bits *= 0.8; issues.push('Repeated characters'); }
  if (/(012|123|234|345|456|567|678|789|abc|bcd|cde|qwe|asd)/i.test(pw)) { bits *= 0.85; issues.push('Sequential pattern'); }
  if (pw.length < 12) issues.push('Shorter than 12 characters');
  const seconds = 2 ** bits / 1e10 / 2; // offline fast hash, 10B guesses/s
  const human = seconds < 1 ? 'instantly' : seconds < 3600 ? `${Math.round(seconds / 60)} minutes` : seconds < 86400 * 365 ? `${Math.round(seconds / 86400)} days`
    : seconds < 86400 * 365 * 1e6 ? `${Math.round(seconds / (86400 * 365)).toLocaleString()} years` : 'millions of years+';
  const level = bits < 40 ? ['Very weak', '#f87171'] : bits < 60 ? ['Weak', '#fbbf24'] : bits < 80 ? ['Reasonable', '#38bdf8'] : ['Strong', '#22d3a6'];
  return { bits: Math.round(bits), human, level, issues };
}

function PasswordTool() {
  const [pw, setPw] = useState('');
  const [len, setLen] = useState(20);
  const [sets, setSets] = useState({ lower: true, upper: true, digits: true, symbols: true });
  const s = strength(pw);
  const generate = () => {
    const chars = (sets.lower ? 'abcdefghijkmnopqrstuvwxyz' : '') + (sets.upper ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : '') + (sets.digits ? '23456789' : '') + (sets.symbols ? '!@#$%^&*()-_=+[]{};:,.?' : '');
    if (!chars) return;
    const buf = new Uint32Array(len);
    crypto.getRandomValues(buf);
    setPw([...buf].map((n) => chars[n % chars.length]).join(''));
  };
  return (
    <div className="flex flex-col gap-4">
      <div className="flex gap-2">
        <Input mono value={pw} onChange={(e) => setPw(e.target.value)} placeholder="Type a password to test, or generate one" />
        {pw && <CopyButton text={pw} />}
      </div>
      <div className="flex flex-wrap items-center gap-4 text-sm">
        <label className="flex items-center gap-2 text-muted">Length
          <input type="range" min="8" max="64" value={len} onChange={(e) => setLen(+e.target.value)} />
          <span className="w-6 font-mono text-text">{len}</span>
        </label>
        {Object.keys(sets).map((k) => (
          <label key={k} className="flex items-center gap-1.5 capitalize text-muted">
            <input type="checkbox" checked={sets[k]} onChange={(e) => setSets({ ...sets, [k]: e.target.checked })} /> {k}
          </label>
        ))}
        <Button variant="primary" icon={Dices} onClick={generate}>Generate</Button>
      </div>
      {s && (
        <div className="rounded-lg border border-line bg-bg p-4">
          <div className="mb-2 flex items-center justify-between text-sm">
            <span style={{ color: s.level[1] }} className="font-semibold">{s.level[0]}</span>
            <span className="font-mono text-xs text-muted">~{s.bits} bits entropy</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-full bg-[#1e2631]">
            <div className="h-full rounded-full" style={{ width: `${Math.min(100, (s.bits / 100) * 100)}%`, background: s.level[1] }} />
          </div>
          <p className="mt-3 text-sm text-muted">Estimated offline crack time (10B guesses/s): <span className="text-text">{s.human}</span></p>
          {s.issues.map((i) => <p key={i} className="mt-1 text-sm text-amber-300">⚠ {i}</p>)}
          <p className="mt-2 text-xs text-[#5b6777]">Evaluated locally; nothing is sent anywhere.</p>
        </div>
      )}
    </div>
  );
}
