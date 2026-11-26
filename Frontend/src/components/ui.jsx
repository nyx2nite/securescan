import { useState } from 'react';
import { Check, Copy, LoaderCircle } from 'lucide-react';
import { SEV_STYLE } from '../lib/util';

export function Card({ className = '', children, ...props }) {
  return (
    <div className={`rounded-xl border border-line bg-panel ${className}`} {...props}>
      {children}
    </div>
  );
}

export function CardHeader({ title, icon: Icon, right, subtitle }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
      <div className="flex items-center gap-2.5 min-w-0">
        {Icon && <Icon size={16} className="text-accent shrink-0" />}
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-text truncate">{title}</h3>
          {subtitle && <p className="text-xs text-muted truncate">{subtitle}</p>}
        </div>
      </div>
      {right}
    </div>
  );
}

export function PageHeader({ title, subtitle, right }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-text">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {right}
    </div>
  );
}

const BTN = {
  primary: 'bg-accent text-[#04140f] hover:brightness-110 font-semibold',
  ghost: 'bg-panel2 text-text border border-line hover:border-[#334155] hover:bg-[#1b2330]',
  danger: 'bg-red-500/10 text-red-300 border border-red-500/30 hover:bg-red-500/20',
};

export function Button({ variant = 'ghost', loading, icon: Icon, children, className = '', ...props }) {
  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer ${BTN[variant]} ${className}`}
      disabled={loading || props.disabled}
      {...props}
    >
      {loading ? <LoaderCircle size={16} className="animate-spin" /> : Icon && <Icon size={16} />}
      {children}
    </button>
  );
}

export function Input({ className = '', mono, ...props }) {
  return (
    <input
      className={`w-full rounded-lg border border-line bg-bg px-3.5 py-2.5 text-sm text-text placeholder:text-[#5b6777] outline-none transition focus:border-accent/60 focus:ring-2 focus:ring-accent/15 ${mono ? 'font-mono' : ''} ${className}`}
      {...props}
    />
  );
}

export function TextArea({ className = '', ...props }) {
  return (
    <textarea
      className={`w-full rounded-lg border border-line bg-bg px-3.5 py-2.5 font-mono text-sm text-text placeholder:text-[#5b6777] outline-none transition focus:border-accent/60 focus:ring-2 focus:ring-accent/15 ${className}`}
      {...props}
    />
  );
}

export function SeverityBadge({ severity }) {
  const s = SEV_STYLE[severity] || SEV_STYLE.info;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ${s.bg} ${s.text} ${s.ring}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {severity}
    </span>
  );
}

export function Pill({ ok, children }) {
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-semibold ring-1 ${ok ? 'bg-emerald-500/10 text-emerald-300 ring-emerald-500/30' : 'bg-red-500/10 text-red-300 ring-red-500/30'}`}>
      {children}
    </span>
  );
}

export function ScoreRing({ score, size = 120, stroke = 10, color }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1e2631" strokeWidth={stroke} />
        <circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c - (c * Math.max(0, Math.min(100, score))) / 100}
          style={{ transition: 'stroke-dashoffset .6s ease' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-semibold leading-none text-text" style={{ fontSize: size * 0.28 }}>{score}</span>
        <span className="text-[11px] text-muted">/ 100</span>
      </div>
    </div>
  );
}

export function ScoreBadge({ score, color }) {
  return (
    <div
      className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg font-mono text-sm font-semibold"
      style={{ color, background: `${color}1f`, boxShadow: `inset 0 0 0 1px ${color}55` }}
    >
      {score}
    </div>
  );
}

export function Spinner({ label }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
      <LoaderCircle size={18} className="animate-spin text-accent" /> {label}
    </div>
  );
}

export function Empty({ icon: Icon, title, children }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {Icon && <Icon size={28} className="text-[#3b4757]" />}
      <p className="text-sm font-medium text-text">{title}</p>
      {children && <div className="text-sm text-muted">{children}</div>}
    </div>
  );
}

export function ErrorBox({ children }) {
  if (!children) return null;
  return <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">{children}</div>;
}

export function CopyButton({ text, className = '' }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      title="Copy"
      onClick={() => {
        navigator.clipboard?.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 1200);
      }}
      className={`rounded-md p-1.5 text-muted transition hover:bg-panel2 hover:text-text cursor-pointer ${className}`}
    >
      {done ? <Check size={14} className="text-accent" /> : <Copy size={14} />}
    </button>
  );
}

export function KV({ label, children, mono }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line/60 py-2.5 last:border-0">
      <span className="shrink-0 text-sm text-muted">{label}</span>
      <span className={`min-w-0 break-all text-right text-sm text-text ${mono ? 'font-mono text-[13px]' : ''}`}>{children}</span>
    </div>
  );
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-line">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`relative flex items-center gap-2 whitespace-nowrap px-3.5 py-2.5 text-sm transition cursor-pointer ${value === t.id ? 'text-text' : 'text-muted hover:text-text'}`}
        >
          {t.icon && <t.icon size={15} />}
          {t.label}
          {t.count != null && <span className="rounded bg-panel2 px-1.5 text-[11px] text-muted">{t.count}</span>}
          {value === t.id && <span className="absolute inset-x-2 -bottom-px h-0.5 rounded bg-accent" />}
        </button>
      ))}
    </div>
  );
}

export function DnsRecords({ records }) {
  return (
    <div className="flex flex-col gap-3">
      {Object.entries(records).filter(([, v]) => v?.length).map(([type, values]) => (
        <div key={type}>
          <div className="mb-1 text-xs font-semibold text-accent">{type}</div>
          {values.map((v, i) => <div key={i} className="break-all font-mono text-xs text-muted">{v}</div>)}
        </div>
      ))}
    </div>
  );
}
