import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  ArrowRight, Cookie, FileWarning, Fingerprint, Globe, Lock, Mail, Network, Radar, ScanSearch, Server, Zap,
} from 'lucide-react';
import { api } from '../lib/api';
import { risk, timeAgo } from '../lib/util';
import { Button, Card, CardHeader, ErrorBox, ScoreBadge } from '../components/ui';

const STEPS = {
  full: ['Resolving target', 'Inspecting TLS certificate', 'Scanning 35 ports + banners', 'Analyzing HTTP headers & cookies',
    'Probing for exposed files', 'Testing CORS & HTTP methods', 'Querying DNS / SPF / DMARC', 'Scoring findings'],
  quick: ['Resolving target', 'Inspecting TLS certificate', 'Scanning 11 common ports', 'Analyzing HTTP headers & cookies',
    'Querying DNS / SPF / DMARC', 'Scoring findings'],
};

const CHECKS = [
  { icon: Lock, title: 'TLS / Certificates', text: 'Validity, expiry, protocol & cipher, legacy TLS 1.0/1.1, HTTPS redirect.' },
  { icon: Network, title: 'Port exposure', text: '35 high-risk service ports with banner grabbing (RDP, SMB, DBs, Redis…).' },
  { icon: Server, title: 'Security headers', text: 'CSP, HSTS, framing, MIME sniffing, referrer & permissions policies.' },
  { icon: FileWarning, title: 'Sensitive files', text: '.git, .env, backups, SQL dumps, phpinfo, server-status, actuator.' },
  { icon: Cookie, title: 'Cookies & CORS', text: 'Secure / HttpOnly / SameSite flags, origin reflection, TRACE.' },
  { icon: Mail, title: 'DNS & email', text: 'SPF, DMARC and CAA records — spoofing & mis-issuance protection.' },
  { icon: Fingerprint, title: 'Fingerprinting', text: 'Server, framework, CMS and CDN detection, version disclosure.' },
  { icon: Zap, title: 'Fast & parallel', text: 'All checks run concurrently — full scans finish in seconds.' },
];

export default function Scanner() {
  const [target, setTarget] = useState('');
  const [profile, setProfile] = useState('full');
  const [scanning, setScanning] = useState(false);
  const [step, setStep] = useState(0);
  const [error, setError] = useState('');
  const [recent, setRecent] = useState([]);
  const timer = useRef();
  const navigate = useNavigate();

  useEffect(() => {
    api('/scans').then((s) => setRecent(s.slice(0, 6))).catch(() => {});
    return () => clearInterval(timer.current);
  }, []);

  const start = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    setScanning(true);
    setError('');
    setStep(0);
    const steps = STEPS[profile];
    timer.current = setInterval(() => setStep((s) => Math.min(s + 1, steps.length - 1)), profile === 'full' ? 380 : 260);
    try {
      const result = await api('/scans', { method: 'POST', body: { domain: target.trim(), profile } });
      navigate(`/scans/${result.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      clearInterval(timer.current);
      setScanning(false);
    }
  };

  const steps = STEPS[profile];

  return (
    <div className="flex flex-col gap-8">
      <section className="relative overflow-hidden rounded-2xl border border-line bg-panel px-8 py-10">
        <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-accent/10 blur-3xl" />
        <div className="relative max-w-3xl">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-3 py-1 text-xs text-accent">
            <Radar size={13} /> Attack-surface scanner
          </div>
          <h1 className="text-3xl font-semibold tracking-tight">Assess a website's security posture</h1>
          <p className="mt-2 text-sm text-muted">
            Enter a domain, URL or IP. SecureScan checks TLS, exposed services, headers, cookies, sensitive files and email security, then scores the target out of 100 with a fix for every finding.
          </p>

          <form onSubmit={start} className="mt-6 flex flex-col gap-3">
            <div className="flex gap-3">
              <div className="relative flex-1">
                <Globe size={17} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  autoFocus
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={scanning}
                  placeholder="example.com, https://app.example.com or 203.0.113.10"
                  className="w-full rounded-xl border border-line bg-bg py-3.5 pl-11 pr-4 font-mono text-sm outline-none transition placeholder:font-sans placeholder:text-[#5b6777] focus:border-accent/60 focus:ring-2 focus:ring-accent/15"
                />
              </div>
              <Button type="submit" variant="primary" loading={scanning} icon={ScanSearch} className="px-6">
                {scanning ? 'Scanning' : 'Scan'}
              </Button>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-muted">Profile:</span>
              {[
                ['full', 'Full audit'],
                ['quick', 'Quick'],
              ].map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  disabled={scanning}
                  onClick={() => setProfile(id)}
                  className={`rounded-md px-2.5 py-1 ring-1 transition cursor-pointer ${profile === id ? 'bg-accent/10 text-accent ring-accent/40' : 'text-muted ring-line hover:text-text'}`}
                >
                  {label}
                </button>
              ))}
              <span className="text-[#5b6777]">
                {profile === 'full' ? '— all checks, ~3–8 s' : '— core checks, no file probing, ~1–3 s'}
              </span>
            </div>
          </form>

          {scanning && (
            <div className="mt-6 rounded-xl border border-line bg-bg p-4 font-mono text-[13px]">
              {steps.map((s, i) => (
                <div key={s} className={`flex items-center gap-2 py-0.5 ${i < step ? 'text-muted' : i === step ? 'text-accent' : 'text-[#3b4757]'}`}>
                  <span className="w-4">{i < step ? '✓' : i === step ? '›' : '·'}</span>
                  {s}
                  {i === step && <span className="animate-pulse">_</span>}
                </div>
              ))}
            </div>
          )}
          <div className="mt-4"><ErrorBox>{error}</ErrorBox></div>
        </div>
      </section>

      <div className="grid gap-6 lg:grid-cols-[1fr_340px]">
        <div className="grid grid-cols-2 gap-3">
          {CHECKS.map(({ icon: Icon, title, text }) => (
            <Card key={title} className="p-4">
              <Icon size={18} className="mb-2 text-accent" />
              <div className="text-sm font-medium">{title}</div>
              <div className="mt-1 text-xs leading-relaxed text-muted">{text}</div>
            </Card>
          ))}
        </div>

        <Card className="self-start">
          <CardHeader title="Recent scans" right={<Link to="/history" className="text-xs text-accent hover:underline">All</Link>} />
          {recent.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-muted">No scans yet.</p>
          ) : (
            <div className="p-2">
              {recent.map((s) => {
                const r = risk(s.score);
                return (
                  <Link key={s.id} to={`/scans/${s.id}`} className="group flex items-center gap-3 rounded-lg px-3 py-2.5 transition hover:bg-panel2">
                    <ScoreBadge score={s.score} color={r.hex} />
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-[13px]">{s.domain}</div>
                      <div className="text-xs text-muted">{timeAgo(s.date)}</div>
                    </div>
                    <ArrowRight size={15} className="text-muted opacity-0 transition group-hover:opacity-100" />
                  </Link>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
