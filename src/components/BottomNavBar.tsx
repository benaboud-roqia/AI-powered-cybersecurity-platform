import { Radio, Terminal, TrendingUp, ShieldAlert } from 'lucide-react';

export type TabType = 'hunter' | 'logs' | 'analysis' | 'reports';

interface BottomNavBarProps {
  currentTab: TabType;
  onTabChange: (tab: TabType) => void;
  activeIncidentsCount: number;
}

export default function BottomNavBar({ currentTab, onTabChange, activeIncidentsCount }: BottomNavBarProps) {
  const navItems = [
    { id: 'hunter' as const, label: 'Hunter', icon: Radio, description: 'Threat Scan' },
    { id: 'logs' as const, label: 'Logs', icon: Terminal, description: 'Event Feed' },
    { id: 'analysis' as const, label: 'Analysis', icon: TrendingUp, description: 'Analytics' },
    { id: 'reports' as const, label: 'Reports', icon: ShieldAlert, description: 'Incidents' },
  ];

  return (
    <nav className="fixed bottom-0 left-0 w-full z-50 flex justify-around items-center px-4 py-2 pb-5 bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg border-t border-slate-100 dark:border-slate-800 shadow-[0_-4px_20px_rgba(0,103,124,0.06)]">
      {navItems.map((item) => {
        const Icon = item.icon;
        const isActive = currentTab === item.id;
        return (
          <button
            key={item.id}
            onClick={() => onTabChange(item.id)}
            id={`nav-tab-${item.id}`}
            className={`relative flex flex-col items-center justify-center transition-all duration-300 py-1.5 px-4 rounded-xl group select-none ${
              isActive
                ? 'bg-sky-50 dark:bg-sky-950/50 text-sky-600 dark:text-sky-450 scale-105'
                : 'text-slate-500 hover:text-slate-900 dark:hover:text-slate-350'
            }`}
          >
            <div className="relative">
              <Icon className={`w-5 h-5 transition-transform duration-300 ${isActive ? 'scale-110 text-sky-600' : 'group-hover:scale-105'}`} />
              {item.id === 'reports' && activeIncidentsCount > 0 && (
                <span className="absolute -top-1.5 -right-1.5 flex h-4 w-4 items-center justify-center rounded-full bg-rose-500 text-[9px] font-bold text-white ring-2 ring-white dark:ring-slate-900">
                  {activeIncidentsCount}
                </span>
              )}
            </div>
            <span className="text-[11px] font-sans font-medium mt-1 tracking-tight">
              {item.label}
            </span>
            {isActive && (
              <span className="absolute bottom-0 w-6 h-0.5 bg-sky-500 dark:bg-sky-400 rounded-full" />
            )}
          </button>
        );
      })}
    </nav>
  );
}
