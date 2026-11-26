import { lazy, Suspense } from 'react';
import { NavLink, Route, Routes } from 'react-router-dom';
import { History, LayoutDashboard, Radar, ShieldCheck, Wrench } from 'lucide-react';
import { Spinner } from './components/ui';
import Scanner from './pages/Scanner';

const Dashboard = lazy(() => import('./pages/Dashboard'));
const HistoryPage = lazy(() => import('./pages/History'));
const ScanDetails = lazy(() => import('./pages/ScanDetails'));
const Tools = lazy(() => import('./pages/Tools'));

const NAV = [
  { to: '/', label: 'Scanner', icon: Radar, end: true },
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/history', label: 'History', icon: History },
  { to: '/tools', label: 'Toolbox', icon: Wrench },
];

export default function App() {
  return (
    <div className="flex h-full">
      <aside className="flex w-56 shrink-0 flex-col border-r border-line bg-panel">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/15 ring-1 ring-accent/40">
            <ShieldCheck size={18} className="text-accent" />
          </div>
          <div>
            <div className="text-sm font-semibold leading-tight">SecureScan</div>
            <div className="text-[11px] text-muted">Security toolkit</div>
          </div>
        </div>
        <nav className="flex flex-col gap-0.5 px-3">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition ${
                  isActive ? 'bg-accent/10 text-accent' : 'text-muted hover:bg-panel2 hover:text-text'
                }`
              }
            >
              <Icon size={17} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-auto px-5 py-4 text-[11px] leading-relaxed text-[#5b6777]">
          Only scan systems you own or are authorized to test.
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-8 py-8">
          <Suspense fallback={<Spinner label="Loading…" />}>
            <Routes>
              <Route path="/" element={<Scanner />} />
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/history" element={<HistoryPage />} />
              <Route path="/scans/:id" element={<ScanDetails />} />
              <Route path="/tools" element={<Tools />} />
              <Route path="/tools/:tool" element={<Tools />} />
              <Route path="*" element={<Scanner />} />
            </Routes>
          </Suspense>
        </div>
      </main>
    </div>
  );
}
