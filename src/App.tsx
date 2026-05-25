import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Sparkles, 
  AlertTriangle, 
  Activity, 
  CheckCircle2, 
  Clock, 
  Terminal, 
  TrendingUp, 
  Radio, 
  Database, 
  Laptop, 
  Server, 
  ChevronRight, 
  Cpu, 
  Lock, 
  Search, 
  Filter, 
  PlusCircle, 
  Bug, 
  RefreshCw,
  Send,
  Eye,
  Settings,
  X,
  BookOpen,
  Wifi,
  Skull,
  Grid
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Cell,
  LineChart,
  Line,
  PieChart,
  Pie,
  Legend
} from 'recharts';

import TopAppBar from './components/TopAppBar';
import BottomNavBar, { TabType } from './components/BottomNavBar';
import { Incident, NetworkNode, SystemAuditLog, RemediationStep } from './types';

export default function App() {
  const [currentTab, setCurrentTab] = useState<TabType>('reports');
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [logs, setLogs] = useState<SystemAuditLog[]>([]);
  const [networkNodes, setNetworkNodes] = useState<NetworkNode[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  
  // Tab states
  const [searchLogQuery, setSearchLogQuery] = useState('');
  const [filterLogLevel, setFilterLogLevel] = useState<string>('all');
  const [aiReportLoading, setAiReportLoading] = useState(false);
  const [aiReportResult, setAiReportResult] = useState<string | null>(null);
  const [activeIncidentIdForAi, setActiveIncidentIdForAi] = useState<string | null>(null);
  const [themeMode, setThemeMode] = useState<'light' | 'dark'>('light');

  // Scanner Tab States
  const [cidrRange, setCidrRange] = useState('10.0.4.0/24');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanSpeed, setScanSpeed] = useState('fast');
  const [scanResults, setScanResults] = useState<any | null>(null);
  const [scannedNodeId, setScannedNodeId] = useState<string | null>(null);

  // New Log Entry State
  const [newLogHost, setNewLogHost] = useState('FIN-X92-WKSTN');
  const [newLogService, setNewLogService] = useState('windows-defender');
  const [newLogMessage, setNewLogMessage] = useState('Suspicious registry key override detected under HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run');
  const [newLogLevel, setNewLogLevel] = useState<'critical' | 'high' | 'medium' | 'low'>('high');
  const [newLogStatus, setNewLogStatus] = useState<'blocked' | 'allowed' | 'alerted' | 'quarantined'>('alerted');
  const [logNotification, setLogNotification] = useState<string | null>(null);

  // Load backend statistics
  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [resInc, resLogs, resNet] = await Promise.all([
        fetch('/api/incidents'),
        fetch('/api/logs'),
        fetch('/api/network')
      ]);

      if (resInc.ok && resLogs.ok && resNet.ok) {
        const incidentsData: Incident[] = await resInc.json();
        const logsData: SystemAuditLog[] = await resLogs.json();
        const netData: NetworkNode[] = await resNet.json();

        setIncidents(incidentsData);
        setLogs(logsData);
        setNetworkNodes(netData);

        // Maintain selection or fallback to CVE-2023-34362 initially
        if (incidentsData.length > 0) {
          if (selectedIncident) {
            const freshSelect = incidentsData.find(i => i.id === selectedIncident.id);
            setSelectedIncident(freshSelect || incidentsData[0]);
          } else {
            // Find CVE-2023-34362 or default first
            const defaultInc = incidentsData.find(i => i.cve === 'CVE-2023-34362') || incidentsData[0];
            setSelectedIncident(defaultInc);
          }
        }
      }
    } catch (err) {
      console.error('Failed to carry data payload sync:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  // Theme support
  useEffect(() => {
    if (themeMode === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [themeMode]);

  // Actions
  const handleToggleRemediation = async (incidentId: string, stepNum: number) => {
    try {
      const response = await fetch(`/api/incidents/${incidentId}/remediation/${stepNum}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.incident) {
          // Update local state smoothly
          setIncidents(prev => prev.map(inc => inc.id === incidentId ? data.incident : inc));
          if (selectedIncident && selectedIncident.id === incidentId) {
            setSelectedIncident(data.incident);
          }
          // Refresh logs & network node state as well because status might have updated
          const [resLogs, resNet] = await Promise.all([
            fetch('/api/logs'),
            fetch('/api/network')
          ]);
          if (resLogs.ok) setLogs(await resLogs.json());
          if (resNet.ok) setNetworkNodes(await resNet.json());
        }
      }
    } catch (err) {
      console.error('Failed to toggle remediation status:', err);
    }
  };

  const handleExecuteAllRemediations = async (incidentId: string) => {
    try {
      const response = await fetch(`/api/incidents/${incidentId}/remediation/execute-all`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.incident) {
          setIncidents(prev => prev.map(inc => inc.id === incidentId ? data.incident : inc));
          if (selectedIncident && selectedIncident.id === incidentId) {
            setSelectedIncident(data.incident);
          }
          // Refresh logs & nodes
          const [resLogs, resNet] = await Promise.all([
            fetch('/api/logs'),
            fetch('/api/network')
          ]);
          if (resLogs.ok) setLogs(await resLogs.json());
          if (resNet.ok) setNetworkNodes(await resNet.json());
          
          // Clear any stale AI report cache so they request fresh analysis if needed
          setAiReportResult(null);
        }
      }
    } catch (err) {
      console.error('Failed to execute bulk remediation cycle:', err);
    }
  };

  const handleAddCustomLog = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const response = await fetch('/api/logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          host: newLogHost,
          service: newLogService,
          message: newLogMessage,
          level: newLogLevel,
          status: newLogStatus
        })
      });

      if (response.ok) {
        const addedLog = await response.json();
        setLogs(prev => [addedLog, ...prev]);
        setLogNotification(`Telemetry Alert logged: [${addedLog.level.toUpperCase()}] ${addedLog.host}`);
        
        // Reset query form fields
        setNewLogMessage('');
        
        setTimeout(() => {
          setLogNotification(null);
        }, 4000);
      }
    } catch (err) {
      console.error('Error in register custom telemetry log:', err);
    }
  };

  // Ask AI response generator (Server side Gemini Proxy)
  const handleQueryAiForensicResponse = async (incidentId: string) => {
    if (aiReportLoading) return;
    setAiReportLoading(true);
    setAiReportResult(null);
    setActiveIncidentIdForAi(incidentId);

    try {
      const response = await fetch('/api/ai/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: incidentId })
      });

      if (response.ok) {
        const data = await response.json();
        setAiReportResult(data.mitigationNotes || 'Unable to retrieve analysis summary.');
      } else {
        setAiReportResult('Failed to render AI forensic pipeline query. Check connection.');
      }
    } catch (err: any) {
      console.error('Internal API client failure:', err);
      setAiReportResult('Error occurred while communicating with the AI Cyber Defense proxy server.');
    } finally {
      setAiReportLoading(false);
    }
  };

  // Trigger Network Threat Scan
  const handleStartThreatScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isScanning) return;

    setIsScanning(true);
    setScanProgress(5);
    setScanResults(null);

    // Simulate scanning metrics with progress ticks
    const scanInterval = setInterval(() => {
      setScanProgress(p => {
        if (p >= 100) {
          clearInterval(scanInterval);
          return 100;
        }
        const increment = scanSpeed === 'fast' ? 15 : 4;
        return Math.min(p + increment, 100);
      });
    }, 200);

    // Hit scan endpoint when done
    setTimeout(async () => {
      try {
        const res = await fetch('/api/hunt/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ targetRange: cidrRange })
        });
        if (res.ok) {
          const results = await res.json();
          setScanResults(results);
          // Sync logs with server to fetch Snort alerts generated during scan
          const resLogs = await fetch('/api/logs');
          if (resLogs.ok) setLogs(await resLogs.json());
        }
      } catch (err) {
        console.error('Vulnerability scanner endpoint timed out or error occurred:', err);
      } finally {
        setIsScanning(false);
      }
    }, 2500);
  };

  const getSeverityBadgeColor = (level: string) => {
    switch (level) {
      case 'critical': return 'bg-rose-50 dark:bg-rose-950/40 text-rose-600 dark:text-rose-400 border-rose-200/50 dark:border-rose-900/40';
      case 'high': return 'bg-amber-50 dark:bg-amber-950/40 text-amber-600 dark:text-amber-400 border-amber-200/50 dark:border-amber-900/40';
      case 'medium': return 'bg-yellow-50 dark:bg-yellow-950/40 text-yellow-600 dark:text-yellow-400 border-yellow-200/50 dark:border-yellow-900/40';
      default: return 'bg-sky-50 dark:bg-sky-950/40 text-sky-600 dark:text-sky-450 border-sky-200/50 dark:border-sky-900/40';
    }
  };

  const getStatusBadgeColor = (status: string) => {
    switch (status) {
      case 'mitigated': return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300';
      case 'quarantined': return 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300';
      case 'investigating': return 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300';
      default: return 'bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300';
    }
  };

  // Helper parser to render Markdown returned by AI elegantly
  const renderMarkdown = (text: string) => {
    if (!text) return null;
    const lines = text.split('\n');
    return lines.map((line, idx) => {
      // Heading level 3 ###
      if (line.startsWith('### ')) {
        return <h3 key={idx} className="text-base font-bold text-slate-900 dark:text-slate-100 mt-4 mb-2 border-b border-slate-100 dark:border-slate-800 pb-1 flex items-center gap-1.5">{line.substring(4)}</h3>;
      }
      // Heading level 4 ####
      if (line.startsWith('#### ')) {
        return <h4 key={idx} className="text-sm font-bold text-sky-700 dark:text-sky-450 mt-3 mb-1">{line.substring(5)}</h4>;
      }
      // Unordered list item
      if (line.trim().startsWith('* ') || line.trim().startsWith('- ')) {
        const textContent = line.trim().substring(2);
        // Replace bold ** markers inside text
        const richText = handleInlineMarkdown(textContent);
        return (
          <li key={idx} className="list-disc ml-4 text-xs text-slate-700 dark:text-slate-300 mb-1 leading-relaxed">
            {richText}
          </li>
        );
      }
      // Codeblock markers
      if (line.trim().startsWith('```')) {
        return null; // Skip raw ticks but codeblock wrapper code takes elements
      }
      // Basic paragraphs
      if (line.trim().length > 0) {
        // Wrap command lines or config lines in specific layout if relevant
        if (line.trim().startsWith('#') || line.trim().startsWith('iptables') || line.trim().startsWith('build_environment') || line.trim().includes('allow_unsigned_tarballs')) {
          return (
            <div key={idx} className="bg-slate-900 text-slate-200 p-2.5 rounded font-mono text-[11px] my-1 border border-slate-800 shadow-inner overflow-x-auto whitespace-pre">
              {line}
            </div>
          );
        }
        return (
          <p key={idx} className="text-xs text-slate-600 dark:text-slate-400 mb-2 leading-relaxed">
            {handleInlineMarkdown(line)}
          </p>
        );
      }
      return <div key={idx} className="h-1.5" />;
    });
  };

  const handleInlineMarkdown = (text: string) => {
    // Regex matching bold elements **bold text** or backticks `code`
    const parts = text.split(/(\*\*.*?\*\*|`.*?`)/);
    return parts.map((part, index) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={index} className="font-semibold text-slate-900 dark:text-slate-100">{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={index} className="px-1.5 py-0.5 bg-slate-100 dark:bg-slate-800 text-rose-600 dark:text-rose-400 font-mono text-[11px] rounded border border-slate-200/50 dark:border-slate-700/60">{part.slice(1, -1)}</code>;
      }
      return part;
    });
  };

  // Filter logs logic
  const filteredLogs = logs.filter(log => {
    const matchesSearch = 
      log.host.toLowerCase().includes(searchLogQuery.toLowerCase()) ||
      log.service.toLowerCase().includes(searchLogQuery.toLowerCase()) ||
      log.message.toLowerCase().includes(searchLogQuery.toLowerCase());
    
    if (filterLogLevel === 'all') return matchesSearch;
    return matchesSearch && log.level === filterLogLevel;
  });

  const activeIncidents = incidents.filter(inc => inc.status !== 'mitigated');

  return (
    <div id="app-root" className={`min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-200 font-sans antialiased pb-28 pt-20 transition-colors duration-300`}>
      {/* Top Bar Navigation */}
      <TopAppBar appName="AI Threat Hunter" />

      {/* Floating Theme / Mode Switch Toolbar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex justify-end gap-3 mb-2 text-xs">
        <button 
          onClick={() => setThemeMode(themeMode === 'light' ? 'dark' : 'light')}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 hover:border-slate-350 dark:hover:border-slate-700 text-slate-700 dark:text-slate-300 rounded-lg shadow-sm transition-all text-xs"
        >
          <span>{themeMode === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode'}</span>
        </button>
        <button 
          onClick={fetchAllData}
          id="btn-refresh-telemetry"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-850 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-lg shadow-sm transition-all text-xs"
          title="Refresh statistics fields from server databases"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Synchroniser</span>
        </button>
      </div>

      {loading && incidents.length === 0 ? (
        <div id="loading-fallback" className="flex flex-col items-center justify-center p-20 text-slate-500">
          <Activity className="w-12 h-12 text-sky-500 animate-spin mb-4" />
          <p className="font-semibold tracking-wider font-mono">CONNECTING THREAT MATRIX DATABASE...</p>
          <p className="text-xs text-slate-400 mt-2">Checking real-time socket relays and port protocols...</p>
        </div>
      ) : (
        <main className="max-w-7xl mx-auto px-4 md:px-6">

          {/* tab = REPORTS */}
          {currentTab === 'reports' && selectedIncident && (
            <div id="tab-reports-container" className="space-y-6">
              
              {/* Split layout: Incident Selector Sidebar on Desktop + Core Dashboard Main View */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Left side sidebar - Incident selector (quick index switch) */}
                <div className="lg:col-span-3 space-y-3">
                  <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                    <h3 className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-3 flex items-center justify-between">
                      <span>Rapports Actifs</span>
                      <span className="p-1 px-1.5 bg-sky-100 dark:bg-sky-950/60 text-sky-600 dark:text-sky-400 text-[10px] rounded-full font-sans font-extrabold">{incidents.length} Tracker</span>
                    </h3>
                    <div className="space-y-2">
                      {incidents.map((inc) => (
                        <button
                          key={inc.id}
                          onClick={() => {
                            setSelectedIncident(inc);
                            setAiReportResult(null); // Clear active report result
                          }}
                          className={`w-full text-left p-3 rounded-xl transition-all border text-xs flex flex-col gap-1.5 ${
                            selectedIncident.id === inc.id
                              ? 'bg-sky-50/70 border-sky-200/80 dark:bg-sky-950/30 dark:border-sky-800/80 text-sky-950 dark:text-sky-100 shadow-sm ring-1 ring-sky-500/20'
                              : 'bg-transparent border-slate-100 hover:border-slate-200 dark:border-transparent dark:hover:bg-slate-850 text-slate-600 dark:text-slate-400'
                          }`}
                        >
                          <div className="flex justify-between items-center w-full">
                            <span className="font-mono font-semibold text-slate-400 dark:text-slate-500 text-[10px]">
                              {inc.cve || inc.id}
                            </span>
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${getStatusBadgeColor(inc.status)}`}>
                              {inc.status}
                            </span>
                          </div>
                          <span className="font-bold line-clamp-1 text-slate-850 dark:text-slate-200">
                            {inc.title}
                          </span>
                          <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-100/50 dark:border-slate-800/50">
                            <span>Score: <strong className="text-rose-500 font-bold">{inc.riskScore}</strong></span>
                            <span className="text-[10px] font-mono italic">{inc.affectedAssets.length} Assets</span>
                          </div>
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Active Threat Matrix Widget */}
                  <div className="p-4 bg-gradient-to-br from-slate-900 to-slate-950 text-slate-200 rounded-xl border border-slate-800 shadow-md relative overflow-hidden hidden lg:block">
                    <div className="absolute right-[-10px] top-[-10px] opacity-10">
                      <Shield className="w-24 h-24 text-sky-500" />
                    </div>
                    <h4 className="text-[10px] font-mono text-sky-400 uppercase tracking-widest font-semibold mb-1 flex items-center gap-1.5">
                      <Wifi className="w-3.5 h-3.5 text-sky-400 animate-pulse" />
                      Système de Quarantaine
                    </h4>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      L'agent d'IA applique automatiquement l'isolation réseau au niveau de l'IP du commutateur de commutation en cas de pic de trafic exfiltré.
                    </p>
                    <div className="mt-3 flex items-center gap-2 text-[10px] bg-sky-950/80 px-2 py-1.5 rounded border border-sky-900/40 text-sky-300 font-mono">
                      <span>Gateway Active: 10.0.1.1</span>
                    </div>
                  </div>
                </div>

                {/* Main Incident Details Area - Mimicking the Screenshot style */}
                <div className="lg:col-span-9 space-y-6 bg-white dark:bg-slate-900/40 p-5 rounded-2xl border border-slate-200/50 dark:border-slate-800/50 shadow-sm">
                  
                  {/* Incident Header */}
                  <div className="pb-4 border-b border-slate-100 dark:border-slate-800">
                    <span className="font-mono text-xs font-semibold text-sky-600 dark:text-sky-400 tracking-wider uppercase block mb-1">
                      Incident Analysis Report
                    </span>
                    <h2 className="font-sans text-2xl font-extrabold text-slate-950 dark:text-slate-100 tracking-tight leading-tight">
                      {selectedIncident.title}
                    </h2>
                    <p className="text-slate-600 dark:text-slate-350 text-xs sm:text-sm mt-2 leading-relaxed max-w-4xl">
                      {selectedIncident.summary}
                    </p>
                  </div>

                  {/* Bento Grid: Threat Narrative Timeline vs Risk Index Gauge */}
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                    
                    {/* Narrative Card (Interactive DOT Timeline - matching screenshots layout closely) */}
                    <div className="md:col-span-8 bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm relative overflow-hidden">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-2">
                          <Sparkles className="w-4 h-4 text-sky-500" />
                          <h3 className="font-sans font-bold text-sm text-slate-900 dark:text-slate-100 uppercase tracking-tight">Threat Narrative</h3>
                        </div>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-500 rounded-full font-semibold">
                          NLP Reconstruction
                        </span>
                      </div>

                      <div className="relative pl-6 space-y-6 pt-1">
                        {/* Vertical Gradient Line Connector */}
                        <div className="absolute left-[9px] top-2 bottom-2 w-0.5 bg-gradient-to-b from-sky-600 via-purple-600 to-rose-600 opacity-40"></div>
                        
                        {selectedIncident.timeline.map((event, index) => {
                          // Dynamic marker coloring
                          let markerColor = 'bg-sky-500 ring-sky-100 dark:ring-sky-950';
                          if (event.type === 'phishing') markerColor = 'bg-sky-500 ring-sky-100 dark:ring-sky-950';
                          else if (event.type === 'escalation') markerColor = 'bg-purple-500 ring-purple-100 dark:ring-purple-950';
                          else if (event.type === 'recon') markerColor = 'bg-indigo-500 ring-indigo-100 dark:ring-indigo-950';
                          else if (event.type === 'blocked') markerColor = 'bg-rose-500 ring-rose-100 dark:ring-rose-950';

                          return (
                            <div key={index} className="relative group transition-all">
                              <div className={`absolute -left-[22px] top-1.5 w-2.5 h-2.5 rounded-full ${markerColor} ring-4 shadow-sm transition-transform duration-200 group-hover:scale-125`}></div>
                              <div className="text-xs">
                                <span className="font-mono font-bold text-slate-400 dark:text-slate-500 text-[10px] block mb-0.5">
                                  {event.time}
                                </span>
                                <h4 className="font-bold text-slate-850 dark:text-slate-100 text-xs mb-1">
                                  {event.title}
                                </h4>
                                <p className="text-slate-600 dark:text-slate-400 leading-relaxed text-[11px]">
                                  {event.text}
                                </p>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Right Side Column (Risk Assessment + Affected Assets Cards) */}
                    <div className="md:col-span-4 flex flex-col gap-6">
                      
                      {/* Risk Assessment block */}
                      <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm flex flex-col justify-between">
                        <div>
                          <h4 className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-3">
                            Risk Assessment
                          </h4>
                          <div className="flex items-baseline gap-2">
                            <span className="font-sans text-3xl font-black text-rose-600 leading-none">
                              {selectedIncident.riskScore}
                            </span>
                            <span className="text-xs font-bold text-rose-600 tracking-wider">
                              CRITICAL
                            </span>
                          </div>
                          {/* Simulated Slider bar matching exact screenshot bar */}
                          <div className="w-full h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full mt-4 relative">
                            <div 
                              className="h-full bg-rose-600 rounded-full transition-all duration-1000"
                              style={{ width: `${selectedIncident.riskScore * 10}%` }}
                            ></div>
                          </div>
                        </div>
                        <div className="text-[10px] text-slate-400 leading-tight mt-3">
                          Score computed based on database sensitivity metrics and vectors scanning factors.
                        </div>
                      </div>

                      {/* Affected Assets block */}
                      <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm flex-1">
                        <h4 className="text-[10px] font-semibold text-slate-400 dark:text-slate-500 uppercase tracking-widest mb-3">
                          Affected Assets
                        </h4>
                        
                        <div className="space-y-3">
                          {selectedIncident.affectedAssets.map((asset, index) => {
                            const isDb = asset.type === 'database';
                            const isServer = asset.type === 'server' || asset.type === 'router';
                            
                            return (
                              <div 
                                key={index} 
                                className="flex items-center gap-3 p-2 bg-slate-50 dark:bg-slate-950 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors rounded-xl border border-slate-100/40 dark:border-slate-800/40"
                              >
                                <div className="p-2 bg-white dark:bg-slate-900 rounded-lg text-slate-500 dark:text-slate-400 shadow-sm">
                                  {isDb ? (
                                    <Database className="w-4 h-4 text-sky-500" />
                                  ) : isServer ? (
                                    <Server className="w-4 h-4 text-emerald-500" />
                                  ) : (
                                    <Laptop className="w-4 h-4 text-purple-500" />
                                  )}
                                </div>
                                <div className="flex flex-col">
                                  <span className="text-xs font-extrabold text-slate-950 dark:text-slate-200">
                                    {asset.name}
                                  </span>
                                  <span className="font-mono text-[10px] text-slate-400">
                                    {asset.ip}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>

                    </div>
                  </div>

                  {/* MITRE ATT&CK Techniques & Remediation Steps Section */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    
                    {/* MITRE Card */}
                    <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-4">
                          <div className="flex items-center gap-2">
                            <Grid className="w-4 h-4 text-purple-500" />
                            <h3 className="font-sans font-bold text-sm text-slate-900 dark:text-slate-100 uppercase tracking-tight">Techniques Used</h3>
                          </div>
                          <span className="text-[10px] font-mono text-purple-500">
                            MITRE ATT&amp;CK v13
                          </span>
                        </div>
                        
                        <div className="space-y-2.5">
                          {selectedIncident.techniques.map((tech) => (
                            <a
                              key={tech.code}
                              href={tech.url}
                              target="_blank"
                              rel="noreferrer"
                              className="p-2 px-3 border border-slate-100 dark:border-slate-800/80 rounded-xl flex justify-between items-center group hover:bg-slate-50 dark:hover:bg-slate-950 transition-all text-xs"
                            >
                              <div className="pr-2">
                                <span className="font-mono font-bold text-purple-600 dark:text-purple-400 block text-[10px]">
                                  {tech.code}
                                </span>
                                <span className="font-semibold text-slate-800 dark:text-slate-200 text-xs">
                                  {tech.name}
                                </span>
                              </div>
                              <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-purple-500 group-hover:translate-x-0.5 transition-all flex-shrink-0" />
                            </a>
                          ))}
                        </div>
                      </div>
                      
                      <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800 text-[10px] text-slate-400 leading-tight">
                        Cliqué sur un badge de vecteur pour interroger la base de données de Mitre d'éducation publique.
                      </div>
                    </div>

                    {/* Remediation Steps Card */}
                    <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-2">
                          <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                          <h3 className="font-sans font-bold text-sm text-slate-900 dark:text-slate-100 uppercase tracking-tight">Remediation Steps</h3>
                        </div>
                        <span className="text-[10px] font-mono text-emerald-500">
                          Interactive Check list
                        </span>
                      </div>

                      <div className="space-y-3">
                        {selectedIncident.remediation.map((step) => {
                          const isCompleted = step.status === 'completed';
                          return (
                            <div 
                              key={step.stepNum}
                              onClick={() => handleToggleRemediation(selectedIncident.id, step.stepNum)}
                              className={`flex gap-3 p-3 rounded-xl border transition-all cursor-pointer ${
                                isCompleted
                                  ? 'bg-emerald-50/50 border-emerald-100 dark:bg-emerald-950/20 dark:border-emerald-900/30'
                                  : 'bg-white border-slate-100 dark:bg-slate-900 dark:border-slate-850 hover:bg-slate-50 dark:hover:bg-slate-850'
                              }`}
                            >
                              <div className="flex-shrink-0 pt-0.5">
                                <button
                                  type="button"
                                  className={`w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] transition-all border ${
                                    isCompleted
                                      ? 'bg-emerald-500 border-emerald-500 text-white'
                                      : 'border-slate-300 dark:border-slate-700 text-slate-550'
                                  }`}
                                >
                                  {isCompleted ? '✓' : step.stepNum}
                                </button>
                              </div>
                              <div className="text-xs">
                                <p className={`font-bold transition-all ${isCompleted ? 'line-through text-slate-450 dark:text-slate-500' : 'text-slate-850 dark:text-slate-200'}`}>
                                  {step.title}
                                </p>
                                <p className="text-slate-500 dark:text-slate-400 text-[10px] mt-0.5 leading-tight">
                                  {step.description}
                                </p>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      <button
                        onClick={() => handleExecuteAllRemediations(selectedIncident.id)}
                        className="mt-4 w-full py-2.5 rounded-full bg-slate-900 hover:bg-slate-800 dark:bg-sky-600 dark:hover:bg-sky-500 text-white text-xs font-bold shadow transition-all active:scale-[0.98] duration-200 flex items-center justify-center gap-1.5"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        Execute All Remediation Tasks
                      </button>
                    </div>

                  </div>

                  {/* Anomalous Traffic Flow Visualizer using Recharts */}
                  <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-100 dark:border-slate-850 shadow-sm">
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                      <div>
                        <h3 className="font-sans font-bold text-sm text-slate-900 dark:text-slate-100 uppercase tracking-tight">Anomalous Traffic Flow</h3>
                        <p className="text-slate-500 dark:text-slate-400 text-xs">Visualizing the outbound exfiltration attempt pattern rate (GB/s)</p>
                      </div>
                      <div className="flex gap-2 text-[10px] font-mono">
                        <span className="px-2.5 py-0.5 bg-rose-50 dark:bg-rose-950/30 text-rose-600 dark:text-rose-400 rounded-full font-bold border border-rose-100 dark:border-rose-900/40">
                          Spike Detected
                        </span>
                        <span className="px-2.5 py-0.5 bg-slate-100 dark:bg-slate-800 text-slate-555 rounded-full font-bold">
                          Real-time Data
                        </span>
                      </div>
                    </div>

                    <div className="h-60 w-full pt-2">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={selectedIncident.trafficData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                          <XAxis 
                            dataKey="time" 
                            stroke="#888888" 
                            fontSize={10} 
                            tickLine={false} 
                            axisLine={false} 
                          />
                          <YAxis 
                            stroke="#888888" 
                            fontSize={10} 
                            tickLine={false} 
                            axisLine={false} 
                            unit=" GB"
                          />
                          <Tooltip 
                            contentStyle={{ 
                              backgroundColor: '#0f172a', 
                              borderColor: '#334155', 
                              color: '#ffffff',
                              borderRadius: '8px',
                              fontSize: '11px'
                            }}
                            labelClassName="text-sky-300 font-bold"
                          />
                          <Bar dataKey="rate" radius={[4, 4, 0, 0]}>
                            {selectedIncident.trafficData.map((entry, index) => (
                              <Cell 
                                key={`cell-${index}`} 
                                fill={entry.isAnomaly ? '#ba1a1a' : '#00677c'} 
                                className="transition-all hover:opacity-80"
                              />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* AI Assisting Forensic Agent Console */}
                  <div className="bg-gradient-to-tr from-slate-500/5 to-sky-500/10 dark:from-sky-950/10 dark:to-slate-900/10 p-5 rounded-xl border border-sky-100 dark:border-sky-900/40 shadow-sm relative">
                    <div className="absolute top-4 right-4 text-[10px] font-mono text-sky-500 flex items-center gap-1">
                      <Cpu className="w-3.5 h-3.5 animate-spin text-sky-500" />
                      Gemini Core v1.5
                    </div>

                    <div className="max-w-2xl mb-4">
                      <h3 className="text-sm font-bold text-sky-950 dark:text-sky-100 flex items-center gap-1.5 leading-none">
                        <Sparkles className="w-4 h-4 text-sky-600 animate-bounce" />
                        AI Forensic Investigation Assistant
                      </h3>
                      <p className="text-[11px] text-slate-600 dark:text-slate-400 mt-2">
                        Query the deep-learning NLP parser engine to reconstruct packet routing, verify SSH dynamic linkers, inspect LSASS hooks, or create custom firewalls.
                      </p>
                    </div>

                    {aiReportResult && activeIncidentIdForAi === selectedIncident.id ? (
                      <div className="bg-white dark:bg-slate-950/80 p-4 rounded-xl border border-sky-100 dark:border-sky-900/30 shadow-inner mt-4">
                        <div className="flex justify-between items-center mb-2 pb-1.5 border-b border-slate-100 dark:border-slate-800">
                          <span className="text-[10px] font-mono text-emerald-500 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                            Generated Defense Insights
                          </span>
                          <button 
                            onClick={() => setAiReportResult(null)}
                            className="text-[10px] text-slate-400 hover:text-slate-650"
                          >
                            <X className="w-3.5 h-3.5" />
                          </button>
                        </div>
                        <div className="prose max-w-full">
                          {renderMarkdown(aiReportResult)}
                        </div>
                        
                        <div className="mt-4 p-2 bg-slate-50 dark:bg-slate-900 rounded border border-slate-200/50 dark:border-slate-800 text-[10px] text-slate-500 flex items-center gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                          <span>Ces propositions de sécurité ont été ajustées en fonction de l'environnement des logs de protection.</span>
                        </div>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleQueryAiForensicResponse(selectedIncident.id)}
                        disabled={aiReportLoading}
                        className="mt-2 text-xs font-bold text-white bg-sky-600 hover:bg-sky-500 dark:bg-sky-700 dark:hover:bg-sky-600 rounded-lg px-4 py-2.5 transition-all outline-none focus:ring-2 focus:ring-sky-500/40 disabled:opacity-60 flex items-center gap-1.5 shadow-sm active:scale-[0.98]"
                      >
                        {aiReportLoading ? (
                          <>
                            <Activity className="w-3.5 h-3.5 animate-spin" />
                            génération des rapports en cours...
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5 text-yellow-300" />
                            Générer une analyse de sécurité par l'IA
                          </>
                        )}
                      </button>
                    )}
                  </div>

                </div>
              </div>
            </div>
          )}

          {/* tab = HUNTER (Vulnerability & Threat Hunting tool) */}
          {currentTab === 'hunter' && (
            <div id="tab-hunter-container" className="space-y-6">
              <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200/50 dark:border-slate-800/50 shadow-sm">
                <div className="flex items-center gap-2 mb-2 pb-3 border-b border-light-divider dark:border-slate-800">
                  <Radio className="w-5 h-5 text-sky-500 animate-pulse" />
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">Contrôleur de Scan &amp; Network Mapping</h2>
                    <p className="text-xs text-slate-450 dark:text-slate-400">Auditer l'infrastructure, isoler les nœuds infectés, et lancer un balayage de vulnérabilités.</p>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 pt-3">
                  
                  {/* Scanner controls form */}
                  <div className="lg:col-span-4 p-4 bg-slate-50 dark:bg-slate-950/80 rounded-xl border border-slate-200/50 dark:border-slate-850">
                    <h3 className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-4">
                      Port &amp; CIDR Sweep Configuration
                    </h3>
                    
                    <form onSubmit={handleStartThreatScan} className="space-y-4 text-xs">
                      <div>
                        <label className="block text-slate-650 dark:text-slate-300 font-semibold mb-1">
                          Masque de Sous-réseau Cible (CIDR)
                        </label>
                        <input
                          type="text"
                          value={cidrRange}
                          onChange={(e) => setCidrRange(e.target.value)}
                          placeholder="e.g. 10.0.4.0/24"
                          className="w-full p-2.5 bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-150 rounded-lg border border-slate-200 dark:border-slate-800 font-mono focus:outline-none focus:border-sky-500"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-slate-655 dark:text-slate-300 font-semibold mb-1">
                            Vitesse de balayage
                          </label>
                          <select
                            value={scanSpeed}
                            onChange={(e) => setScanSpeed(e.target.value)}
                            className="w-full p-2.5 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300"
                          >
                            <option value="fast">Aggressive (Fast)</option>
                            <option value="slow">Stealth (Slow)</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-655 dark:text-slate-300 font-semibold mb-1">
                            Heuristiques snort
                          </label>
                          <select className="w-full p-2.5 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300">
                            <option>Niveau Ultra</option>
                            <option>Standard</option>
                            <option>Désactivé</option>
                          </select>
                        </div>
                      </div>

                      <button
                        type="submit"
                        disabled={isScanning}
                        className="w-full py-2.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white font-bold transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                      >
                        {isScanning ? (
                          <>
                            <Activity className="w-4 h-4 animate-spin" />
                            Analyse de Port... {scanProgress}%
                          </>
                        ) : (
                          <>
                            <Radio className="w-4 h-4" />
                            Démarrer le balayage de sécurité
                          </>
                        )}
                      </button>
                    </form>

                    {isScanning && (
                      <div className="mt-4 space-y-2">
                        <div className="w-full bg-slate-200 dark:bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div 
                            className="bg-sky-500 h-full transition-all duration-300"
                            style={{ width: `${scanProgress}%` }}
                          ></div>
                        </div>
                        <p className="text-[10px] font-mono text-slate-400 animate-pulse text-center">
                          Vérification des signatures sur les ports 22, 80, 443, 8088, 5432...
                        </p>
                      </div>
                    )}

                    {/* Scan results summary */}
                    {scanResults && (
                      <div className="mt-5 p-3.5 bg-sky-950 dark:bg-slate-950 rounded-xl border border-sky-900/60 font-mono text-[11px] text-sky-300 space-y-2">
                        <div className="flex justify-between font-bold border-b border-sky-900/40 pb-1.5 text-xs text-white">
                          <span>RESULTATS DU SCAN</span>
                          <span className="text-[10px] bg-red-900/80 text-white px-1.5 rounded animate-bounce">MENACE TROUVÉE</span>
                        </div>
                        <p>Plage: <span className="text-white">{scanResults.scannedRange}</span></p>
                        <p>Statut: <span className="text-yellow-400">{scanResults.status}</span></p>
                        <p>Noeuds Scannés: <span className="text-white">{scanResults.nodesScanned}</span></p>
                        <p>Menaces Spécifiques: <span className="text-rose-405 text-rose-400 font-bold">{scanResults.threatsDetected}</span></p>
                        
                        <div className="mt-2.5 pt-2 border-t border-sky-900/30 text-[10px] space-y-1.5 text-slate-300">
                          <p className="font-bold text-white uppercase text-[8px]">Critères d'analyse:</p>
                          {scanResults.criticalFindings?.map((item: any, idx: number) => (
                            <div key={idx} className="bg-slate-900/90 p-1.5 rounded border border-sky-950">
                              <span className="text-rose-400 font-bold block">{item.host} ({item.ip})</span>
                              <span className="text-slate-400">{item.threat}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Right side - Visual Threat Map */}
                  <div className="lg:col-span-8 space-y-4">
                    <div className="bg-slate-50 dark:bg-slate-950/40 p-4 border border-slate-200/50 dark:border-slate-800 rounded-xl relative overflow-hidden">
                      <div className="absolute top-2 right-2 flex items-center gap-2">
                        <span className="flex h-2 w-2 relative">
                          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        <span className="font-mono text-[9px] text-emerald-500">DYNAMIC TOPOLOGY</span>
                      </div>

                      <h3 className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5 mb-4">
                        <Grid className="w-3.5 h-3.5 text-slate-500" />
                        Représentation Graphique de l'infrastructure Réseau
                      </h3>

                      {/* Flex grids of Interactive Nodes */}
                      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4 p-2">
                        {networkNodes.map((node) => {
                          const isCompromised = node.status === 'infected';
                          const isWarning = node.status === 'warning';
                          const isQuarantined = node.status === 'quarantined';
                          
                          let cardBorder = 'border-slate-150 dark:border-slate-805';
                          let titleStyle = 'text-slate-800 dark:text-slate-250';
                          let pillBg = 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-600 dark:text-emerald-400';
                          
                          if (isCompromised) {
                            cardBorder = 'border-rose-500/80 animate-pulse ring-1 ring-rose-500/20';
                            titleStyle = 'text-rose-700 dark:text-rose-450 font-bold';
                            pillBg = 'bg-rose-100 text-rose-800 dark:bg-rose-950 font-bold';
                          } else if (isWarning) {
                            cardBorder = 'border-amber-400 ring-1 ring-amber-400/10';
                            titleStyle = 'text-amber-700 dark:text-amber-450';
                            pillBg = 'bg-amber-100 text-amber-800 dark:bg-amber-950';
                          } else if (isQuarantined) {
                            cardBorder = 'border-indigo-400';
                            titleStyle = 'text-indigo-700 dark:text-indigo-450';
                            pillBg = 'bg-indigo-100 text-indigo-800 dark:bg-indigo-950';
                          }

                          return (
                            <div
                              key={node.id}
                              onClick={() => setScannedNodeId(node.id === scannedNodeId ? null : node.id)}
                              className={`p-3 rounded-xl border bg-white dark:bg-slate-900 text-xs shadow-sm hover:translate-y-[-1px] transition-all cursor-pointer ${cardBorder}`}
                            >
                              <div className="flex items-center justify-between gap-1 w-full mb-2">
                                <span className={`text-[8px] font-mono px-1.5 py-0.5 rounded-full uppercase tracking-tight ${pillBg}`}>
                                  {node.status}
                                </span>
                                {node.type === 'database' && <Database className="w-4 h-4 text-sky-505 text-sky-550" />}
                                {node.type === 'server' && <Server className="w-4 h-4 text-purple-550" />}
                                {node.type === 'attacker' && <Skull className="w-4 h-4 text-rose-600 animate-bounce" />}
                                {node.type === 'workstation' && <Laptop className="w-4 h-4 text-indigo-505 text-indigo-550" />}
                              </div>

                              <p className={`font-semibold line-clamp-1 leading-tight ${titleStyle}`}>
                                {node.label}
                              </p>
                              <p className="font-mono text-[9px] text-slate-400 mt-0.5">{node.ip}</p>

                              {/* Connections toggle info */}
                              {scannedNodeId === node.id && (
                                <div className="mt-2.5 pt-2 border-t border-slate-100 dark:border-slate-800 text-[10px] space-y-1 text-slate-500">
                                  <p className="font-bold text-slate-400 uppercase text-[8px]">Séquence réseau:</p>
                                  <p>Liaisons: {node.connections.map(cId => {
                                    const matchingNode = networkNodes.find(n => n.id === cId);
                                    return matchingNode ? `${matchingNode.label}` : `Node ${cId}`;
                                  }).join(', ')}</p>
                                  
                                  {/* Quick Isolation tool */}
                                  <div className="pt-2 flex gap-1">
                                    <button 
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        // Update state: Quarantine / Restore node
                                        setNetworkNodes(prev => prev.map(n => {
                                          if (n.id === node.id) {
                                            const updatedStatus = n.status === 'quarantined' ? 'secure' : 'quarantined';
                                            return { ...n, status: updatedStatus };
                                          }
                                          return n;
                                        }));
                                      }}
                                      className="px-2 py-1 bg-slate-900 dark:bg-slate-800 text-white rounded text-[8px] hover:bg-slate-800 font-bold"
                                    >
                                      {node.status === 'quarantined' ? 'Désisoler' : 'Quarantaine'}
                                    </button>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>

                    </div>

                    {/* Threat mitigation playbook instructions */}
                    <div className="bg-slate-900 text-slate-200 p-4 rounded-xl border border-slate-800 font-mono text-xs space-y-2">
                      <div className="flex items-center gap-1.5 font-sans font-bold text-sky-400">
                        <Terminal className="w-4 h-4" />
                        <span>Interactive Threat Mitigation Engine Terminal</span>
                      </div>
                      <p className="text-[11px] text-slate-300">
                        Select any asset node above to inspect its IP gateway protocol parameters. Under active risk scenario levels, deploying a switches blacklist immediately halts the infection horizontal sweeps.
                      </p>
                    </div>

                  </div>

                </div>
              </div>
            </div>
          )}

          {/* tab = LOGS (Raw live telemetry auditing with dynamic injection) */}
          {currentTab === 'logs' && (
            <div id="tab-logs-container" className="space-y-6">
              
              {logNotification && (
                <div id="log-alert-toaster" className="p-3 bg-rose-500 text-white rounded-xl shadow-md text-xs font-bold font-mono animate-bounce flex items-center justify-between">
                  <span>⚠️ NOTIFICATION SECONDAIRE: {logNotification}</span>
                  <button onClick={() => setLogNotification(null)} className="text-white">✕</button>
                </div>
              )}

              <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200/50 dark:border-slate-800/50 shadow-sm">
                
                {/* Header and Filter Inputs */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-100 dark:border-slate-800 mb-4">
                  <div>
                    <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5">
                      <Terminal className="w-5 h-5 text-sky-500" />
                      Auditeur de Télémétrie Log en Temps Réel
                    </h2>
                    <p className="text-xs text-slate-500 dark:text-slate-400">Suivre les alertes et les tentatives de connexion suspectes sur l'ensemble de l'infrastructure.</p>
                  </div>

                  <div className="flex flex-wrap gap-2.5">
                    {/* Search Field */}
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-400" />
                      <input
                        type="text"
                        value={searchLogQuery}
                        onChange={(e) => setSearchLogQuery(e.target.value)}
                        placeholder="Filtrer par host, service, message..."
                        className="p-2 pl-8 text-xs bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-805 text-slate-700 dark:text-slate-200 focus:outline-none focus:border-sky-500 w-48 sm:w-64"
                      />
                    </div>

                    {/* Level Select */}
                    <div className="flex items-center gap-1">
                      <Filter className="w-3.5 h-3.5 text-slate-400" />
                      <select
                        value={filterLogLevel}
                        onChange={(e) => setFilterLogLevel(e.target.value)}
                        className="p-2 text-xs bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-805 text-slate-705 dark:text-slate-300"
                      >
                        <option value="all">Tous Grades</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                  
                  {/* Left Column - Logs tabular view */}
                  <div className="lg:col-span-8 bg-slate-50 dark:bg-slate-950/40 border border-slate-100 dark:border-slate-800 rounded-xl overflow-hidden">
                    <div className="p-3 bg-white dark:bg-slate-900 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs font-bold text-slate-400">
                      <span>Flux de Télémétrie</span>
                      <span>{filteredLogs.length} Entrées Spécifiées</span>
                    </div>

                    <div className="divide-y divide-slate-100 dark:divide-slate-850 max-h-[500px] overflow-y-auto">
                      {filteredLogs.length === 0 ? (
                        <div className="p-10 text-center text-slate-400 text-xs font-mono">
                          AUCUN LOG NE CORRESPOND AUX CRITERES SPÉCIFIÉS.
                        </div>
                      ) : (
                        filteredLogs.map((log) => {
                          const badgedStyle = getSeverityBadgeColor(log.level);
                          return (
                            <div 
                              key={log.id} 
                              className="p-3.5 hover:bg-white dark:hover:bg-slate-900/60 transition-colors text-xs space-y-1.5 relative group"
                            >
                              <div className="flex flex-wrap items-center justify-between gap-2.5">
                                <div className="flex items-center gap-2">
                                  <span className={`px-2 py-0.5 rounded text-[9px] font-mono tracking-widest font-bold border uppercase ${badgedStyle}`}>
                                    {log.level}
                                  </span>
                                  <span className="font-mono font-bold text-slate-900 dark:text-slate-200 text-[11px]">
                                    {log.host}
                                  </span>
                                  <span className="text-[10px] text-slate-400 font-mono">
                                    • {log.service}
                                  </span>
                                </div>
                                <span className="font-mono text-[10px] text-slate-400 dark:text-slate-550">
                                  {new Date(log.timestamp).toLocaleTimeString()}
                                </span>
                              </div>

                              <p className="text-slate-650 dark:text-slate-300 leading-relaxed font-mono text-[11px] bg-white/40 dark:bg-slate-900/40 p-2 rounded border border-slate-100/50 dark:border-slate-850/50">
                                {log.message}
                              </p>

                              <div className="flex items-center justify-between text-[10px] text-slate-400">
                                <span>Statut: <span className="text-slate-600 dark:text-slate-350 font-bold uppercase">{log.status}</span></span>
                                <span className="font-mono text-[9px] text-slate-400 p-0.5 bg-slate-100 dark:bg-slate-800 rounded">
                                  ID: {log.id}
                                </span>
                              </div>
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>

                  {/* Right Column - Inject manually custom Logs Form */}
                  <div className="lg:col-span-4 p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                    <h3 className="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-1">
                      <PlusCircle className="w-4 h-4 text-sky-505" />
                      Injecteur de Télémétrie suspecte
                    </h3>

                    <form onSubmit={handleAddCustomLog} className="space-y-4 text-xs">
                      <div>
                        <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">
                          Terminal Cible (Hostname)
                        </label>
                        <select
                          value={newLogHost}
                          onChange={(e) => {
                            setNewLogHost(e.target.value);
                            // Auto-set matching services path
                            if (e.target.value === 'DB-PROD-01') setNewLogService('postgres-engine');
                            else if (e.target.value === 'PROD-SSH-GATE') setNewLogService('ssshd');
                            else setNewLogService('windows-defender');
                          }}
                          className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-800 text-slate-800 dark:text-slate-200"
                        >
                          <option value="FIN-X92-WKSTN">FIN-X92-WKSTN (Finance Workstation)</option>
                          <option value="DB-PROD-01">DB-PROD-01 (Main Client Database)</option>
                          <option value="PROD-SSH-GATE">PROD-SSH-GATE (SSH Ingress Gateway)</option>
                          <option value="HR-Laptop-03">HR-Laptop-03 (Laptop End-User)</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">
                          Service Moniteur
                        </label>
                        <input
                          type="text"
                          value={newLogService}
                          onChange={(e) => setNewLogService(e.target.value)}
                          className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 rounded-lg border border-slate-200 dark:border-slate-805 font-mono"
                        />
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">
                            Gravité
                          </label>
                          <select
                            value={newLogLevel}
                            onChange={(e: any) => setNewLogLevel(e.target.value)}
                            className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-805 text-slate-700 dark:text-slate-300 font-bold"
                          >
                            <option value="critical">🔴 Critical</option>
                            <option value="high">🟠 High</option>
                            <option value="medium">🟡 Medium</option>
                            <option value="low">🟢 Low</option>
                          </select>
                        </div>
                        <div>
                          <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">
                            Action Prise
                          </label>
                          <select
                            value={newLogStatus}
                            onChange={(e: any) => setNewLogStatus(e.target.value)}
                            className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-200 dark:border-slate-805 text-slate-705 dark:text-slate-300"
                          >
                            <option value="alerted">Alerted Only</option>
                            <option value="blocked">Blocked Outbound</option>
                            <option value="quarantined">Host Sanitized</option>
                            <option value="allowed">Allowed</option>
                          </select>
                        </div>
                      </div>

                      <div>
                        <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">
                          Message de Télémétrie Log
                        </label>
                        <textarea
                          rows={3}
                          value={newLogMessage}
                          onChange={(e) => setNewLogMessage(e.target.value)}
                          className="w-full p-2.5 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-150 rounded-lg border border-slate-200 dark:border-slate-805 font-mono text-[11px] focus:outline-none focus:border-sky-500"
                        />
                      </div>

                      <button
                        type="submit"
                        className="w-full py-2.5 rounded-lg bg-slate-900 hover:bg-slate-850 dark:bg-sky-600 dark:hover:bg-sky-500 text-white font-bold transition-all shadow-sm active:scale-[0.98] flex items-center justify-center gap-1"
                      >
                        <Send className="w-3.5 h-3.5" />
                        Injecter l'indicateur d'infraction
                      </button>
                    </form>

                  </div>

                </div>

              </div>
            </div>
          )}

          {/* tab = ANALYSIS (Recharts high-level analytics for security managers) */}
          {currentTab === 'analysis' && (
            <div id="tab-analysis-container" className="space-y-6">
              
              {/* KPIs Header */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                
                <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                  <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider block">
                    Indice d'exposition
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="font-sans text-2xl font-black text-rose-500">
                      78.2%
                    </span>
                    <span className="text-[10px] text-rose-500 font-bold">CRITIQUE</span>
                  </div>
                  <span className="text-[9px] text-slate-400 block mt-1">Calculé sur 3 CVE-202X isolées</span>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                  <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider block">
                    Infractions Bloquées
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="font-sans text-2xl font-black text-emerald-500">
                      1,842
                    </span>
                    <span className="text-[10px] text-emerald-400 font-bold">▲ 12%</span>
                  </div>
                  <span className="text-[9px] text-slate-400 block mt-1">Filtrées sur la gateway Snort</span>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                  <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider block">
                    Hôtes en Quarantaine
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="font-sans text-2xl font-black text-amber-500">
                      {networkNodes.filter(n => n.status === 'quarantined').length} / {networkNodes.length}
                    </span>
                  </div>
                  <span className="text-[9px] text-slate-400 block mt-1">Désaccouplés par isolation ARP</span>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 rounded-xl border border-slate-200/60 dark:border-slate-800 shadow-sm">
                  <span className="text-[10px] font-mono font-bold text-slate-400 dark:text-slate-500 uppercase tracking-wider block">
                    Rétablissement IA
                  </span>
                  <div className="flex items-baseline gap-2 mt-2">
                    <span className="font-sans text-2xl font-black text-sky-505 text-sky-500">
                      94.5%
                    </span>
                    <span className="text-[10px] text-sky-400 font-bold">EXCELLENT</span>
                  </div>
                  <span className="text-[9px] text-slate-400 block mt-1">Reconnaissance de motifs réussie</span>
                </div>

              </div>

              {/* Recharts Graphical Visuals */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Traffic Spike and Port attacks chart */}
                <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200/50 dark:border-slate-800/50 shadow-sm">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-tight mb-2">
                    Intensité des scans d'attaques
                  </h3>
                  <p className="text-xs text-slate-500 mb-4">Volume cumulé des tentatives d'infraction observées par plage horaire.</p>
                  
                  <div className="h-64">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart 
                        data={[
                          { hour: '16:00', volume: 15 },
                          { hour: '17:00', volume: 22 },
                          { hour: '18:00', volume: 18 },
                          { hour: '19:00', volume: 38 },
                          { hour: '20:00', volume: 110 },
                          { hour: '21:00', volume: 45 },
                          { hour: '22:00', volume: 30 }
                        ]}
                        margin={{ top: 10, right: 10, left: -25, bottom: 0 }}
                      >
                        <XAxis dataKey="hour" fontSize={10} tickLine={false} />
                        <YAxis fontSize={10} tickLine={false} />
                        <Tooltip />
                        <Line type="monotone" dataKey="volume" stroke="#00677c" strokeWidth={3} activeDot={{ r: 8 }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Threat categories distribution */}
                <div className="bg-white dark:bg-slate-900 p-5 rounded-2xl border border-slate-200/50 dark:border-slate-800/50 shadow-sm">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-slate-100 uppercase tracking-tight mb-2">
                    Classification des vecteurs
                  </h3>
                  <p className="text-xs text-slate-500 mb-4 font-normal">Classification par nature d'attaque d'après l'audit MITRE.</p>

                  <div className="h-64 flex items-center justify-center">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: 'Phishing', value: 40, fill: '#00677c' },
                            { name: 'Supply Chain compromised', value: 30, fill: '#5d3fe0' },
                            { name: 'Credentials scan leaks', value: 20, fill: '#ba1a1a' },
                            { name: 'Local Privilege escalation', value: 10, fill: '#e6a100' }
                          ]}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={90}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {/* Label values rendering inside tooltip handles */}
                        </Pie>
                        <Tooltip />
                        <Legend wrapperStyle={{ fontSize: '11px' }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>

              </div>

              {/* Threat Matrix analysis log review */}
              <div className="bg-slate-900 text-slate-100 p-5 rounded-xl border border-slate-800 text-xs">
                <h4 className="text-sky-400 font-bold uppercase tracking-wide mb-2 flex items-center gap-1.5">
                  <Shield className="w-4 h-4 text-sky-505" />
                  Bilan du Directeur de Sécurité (CISO Summary)
                </h4>
                <p className="text-slate-300 leading-relaxed font-sans text-xs">
                  Notre tracker d'intelligence de menace prouve que la détection d'anomalies de port reste le moyen d'isolation automatisée le plus crucial. En arrêtant le canal de liaison C2 à 04:18 UTC (CVE-2023-34362), le sous-système de défense a préservé l'intégrité de la table SQL du master client. La poursuite des rotations de jetons administrateur s'impose.
                </p>
              </div>

            </div>
          )}

        </main>
      )}

      {/* Global Bottom Tab Bar Navigation component */}
      <BottomNavBar 
        currentTab={currentTab} 
        onTabChange={(tab: TabType) => {
          setCurrentTab(tab);
          // Set to default element if selecting reports again
          if (tab === 'reports' && !selectedIncident && incidents.length > 0) {
            setSelectedIncident(incidents[0]);
          }
        }} 
        activeIncidentsCount={activeIncidents.length}
      />
    </div>
  );
}
