import { Shield, Sparkles, AlertTriangle } from 'lucide-react';

interface TopAppBarProps {
  appName: string;
}

export default function TopAppBar({ appName }: TopAppBarProps) {
  return (
    <header className="flex justify-between items-center w-full px-4 md:px-6 h-16 fixed top-0 z-50 bg-white/80 dark:bg-slate-900/80 backdrop-blur-xl border-b border-slate-100 dark:border-slate-800 shadow-sm transition-colors duration-300">
      <div className="flex items-center gap-2">
        <div className="p-1.5 bg-sky-50 dark:bg-sky-950/50 rounded-lg text-sky-600 dark:text-sky-400">
          <Shield className="w-6 h-6 animate-pulse" />
        </div>
        <div className="flex flex-col">
          <h1 className="font-sans text-lg font-bold text-slate-900 dark:text-slate-100 tracking-tight leading-tight flex items-center gap-1.5">
            {appName}
            <span className="inline-flex items-center rounded-full bg-emerald-50 dark:bg-emerald-950 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:text-emerald-400 border border-emerald-100 dark:border-emerald-900">
              <span className="w-1.5 h-1.5 mr-1 rounded-full bg-emerald-500 animate-pulse"></span>
              Live Defense
            </span>
          </h1>
        </div>
      </div>
      <div className="flex items-center gap-3">
        <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 bg-amber-50 dark:bg-amber-950/40 border border-amber-200/40 dark:border-amber-900/40 rounded-full text-xs text-amber-700 dark:text-amber-400 font-medium font-mono">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
          CVE Scan Active
        </div>
        <div className="w-9 h-9 rounded-full bg-sky-100 dark:bg-sky-950 flex items-center justify-center text-sky-800 dark:text-sky-200 font-bold text-sm tracking-wider border border-sky-200 dark:border-sky-800 shadow-inner">
          JD
        </div>
      </div>
    </header>
  );
}
