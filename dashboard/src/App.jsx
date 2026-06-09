import { useState, useEffect, useCallback } from "react"
import { Shield, Cpu, FileSearch, Brain, Wifi, AlertTriangle, CheckCircle, Clock, RefreshCw, Activity } from "lucide-react"

const API = "http://localhost:8000"

const useFetch = (endpoint, interval = 10000) => {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const fetch_ = useCallback(async () => {
    try {
      const r = await fetch(API + endpoint)
      setData(await r.json())
    } catch(e) { console.error(endpoint, e) }
    finally { setLoading(false) }
  }, [endpoint])
  useEffect(() => {
    fetch_()
    const t = setInterval(fetch_, interval)
    return () => clearInterval(t)
  }, [fetch_, interval])
  return { data, loading, refetch: fetch_ }
}

const verdictColor = (v) => {
  if (!v) return "text-gray-400"
  v = v.toUpperCase()
  if (["MALICIOUS","HIGH_RISK","FLAGGED"].includes(v)) return "text-red-500"
  if (["SUSPICIOUS","QUARANTINE"].includes(v))         return "text-yellow-500"
  if (["CLEAN","BENIGN","ALLOW"].includes(v))          return "text-green-500"
  return "text-blue-400"
}

const verdictBg = (v) => {
  if (!v) return "bg-gray-800/60 border-gray-700/50"
  v = v.toUpperCase()
  if (["MALICIOUS","HIGH_RISK","FLAGGED"].includes(v)) return "bg-red-900/40 border-red-700/50"
  if (["SUSPICIOUS","QUARANTINE"].includes(v))         return "bg-yellow-900/40 border-yellow-700/50"
  if (["CLEAN","BENIGN","ALLOW"].includes(v))          return "bg-green-900/40 border-green-700/50"
  return "bg-gray-800/60 border-gray-700/50"
}

const ts = (t) => t ? new Date(t).toLocaleTimeString("en-IN", {hour:"2-digit",minute:"2-digit",second:"2-digit"}) : "—"

const Stat = ({ label, value, sub, color="text-white" }) => (
  <div className="bg-gray-800/60 border border-gray-700/50 rounded-xl p-4">
    <div className="text-xs text-gray-400 mb-1">{label}</div>
    <div className={`text-2xl font-semibold ${color}`}>{value ?? "—"}</div>
    {sub && <div className="text-xs text-gray-500 mt-1">{sub}</div>}
  </div>
)

const Section = ({ icon: Icon, title, count }) => (
  <div className="flex items-center gap-2 mb-3">
    <Icon size={16} className="text-blue-400" />
    <span className="text-sm font-medium text-gray-200">{title}</span>
    {count !== undefined && <span className="ml-auto text-xs text-gray-500">{count} records</span>}
  </div>
)

const AlertFeed = () => {
  const { data } = useFetch("/api/alerts", 8000)
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-xl p-4">
      <Section icon={AlertTriangle} title="Live alert feed" count={data?.length} />
      <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
        {!data?.length && <div className="text-xs text-gray-500 py-4 text-center">No alerts yet</div>}
        {data?.map((a,i) => (
          <div key={i} className={`border rounded-lg px-3 py-2 ${verdictBg(a.severity)}`}>
            <div className="flex items-center gap-2">
              <span className={`text-xs font-medium uppercase ${verdictColor(a.severity)}`}>{a.type}</span>
              <span className="text-xs text-gray-300 truncate flex-1">{a.title}</span>
              <span className="text-xs text-gray-500">{ts(a.timestamp)}</span>
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className={`text-xs font-semibold ${verdictColor(a.severity)}`}>{a.severity}</span>
              <span className="text-xs text-gray-500">score: {a.score}</span>
              {a.flags?.slice(0,2).map((f,j) => (
                <span key={j} className="text-xs bg-gray-700/60 text-gray-400 px-2 py-0.5 rounded-full">{f}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

const SandboxTable = () => {
  const { data } = useFetch("/api/sandbox", 15000)
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-xl p-4">
      <Section icon={FileSearch} title="Sandbox results" count={data?.length} />
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-700/50">
              <th className="text-left pb-2 font-medium">File</th>
              <th className="text-left pb-2 font-medium">Verdict</th>
              <th className="text-left pb-2 font-medium">Score</th>
              <th className="text-left pb-2 font-medium">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {!data?.length && <tr><td colSpan={4} className="text-gray-500 py-4 text-center">No sandbox results yet</td></tr>}
            {data?.map(r => (
              <tr key={r.id} className="hover:bg-gray-800/30">
                <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{r.file_name}</td>
                <td className={`py-1.5 pr-3 font-medium ${verdictColor(r.verdict)}`}>{r.verdict}</td>
                <td className="py-1.5 pr-3 text-gray-400">{r.threat_score}</td>
                <td className="py-1.5 text-gray-500">{ts(r.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

const AITable = () => {
  const { data } = useFetch("/api/assessments", 15000)
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-xl p-4">
      <Section icon={Brain} title="AI assessments" count={data?.length} />
      <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
        {!data?.length && <div className="text-xs text-gray-500 py-4 text-center">No assessments yet</div>}
        {data?.map(r => (
          <div key={r.id} className={`border rounded-lg px-3 py-2 ${verdictBg(r.verdict)}`}>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-gray-300 font-medium truncate flex-1">{r.file_name}</span>
              <span className={`text-xs font-semibold uppercase ${verdictColor(r.recommended_action)}`}>{r.recommended_action}</span>
            </div>
            <div className="flex gap-3 text-xs text-gray-400">
              <span className={`font-medium ${verdictColor(r.threat_type)}`}>{r.threat_type?.toUpperCase()}</span>
              <span>confidence: {r.confidence}</span>
              <span className="ml-auto text-gray-500">{ts(r.timestamp)}</span>
            </div>
            {r.what_it_does && <div className="text-xs text-gray-500 mt-1 truncate">{r.what_it_does}</div>}
          </div>
        ))}
      </div>
    </div>
  )
}

const NetworkMap = () => {
  const { data } = useFetch("/api/network", 30000)
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-xl p-4">
      <Section icon={Wifi} title="Network devices" count={data?.length} />
      <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
        {!data?.length && <div className="text-xs text-gray-500 py-4 text-center">No scan data yet — run signal_detector.py</div>}
        {data?.map(d => {
          const risk = d.threat_score >= 50 ? "HIGH_RISK" : d.threat_score >= 20 ? "SUSPICIOUS" : "CLEAN"
          return (
            <div key={d.id} className={`border rounded-lg px-3 py-2 ${verdictBg(risk)}`}>
              <div className="flex items-center gap-2">
                {d.is_trusted
                  ? <CheckCircle size={12} className="text-green-500 flex-shrink-0" />
                  : <AlertTriangle size={12} className="text-yellow-500 flex-shrink-0" />}
                <span className="text-xs text-gray-200 font-medium">{d.ip}</span>
                <span className="text-xs text-gray-500">{d.vendor !== "unknown" ? d.vendor : d.mac}</span>
                <span className={`ml-auto text-xs font-semibold ${verdictColor(risk)}`}>{d.threat_score}</span>
              </div>
              {d.open_ports?.length > 0 && (
                <div className="flex gap-1 mt-1 flex-wrap">
                  {d.open_ports.map((p,i) => (
                    <span key={i} className="text-xs bg-gray-700/60 text-gray-400 px-2 py-0.5 rounded-full">{p.service}</span>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

const ProcessFeed = () => {
  const { data } = useFetch("/api/processes", 10000)
  return (
    <div className="bg-gray-900/80 border border-gray-700/50 rounded-xl p-4">
      <Section icon={Cpu} title="Process monitor" count={data?.length} />
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-gray-500 border-b border-gray-700/50">
              <th className="text-left pb-2 font-medium">Process</th>
              <th className="text-left pb-2 font-medium">PID</th>
              <th className="text-left pb-2 font-medium">Score</th>
              <th className="text-left pb-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {!data?.length && <tr><td colSpan={4} className="text-gray-500 py-4 text-center">No process events yet</td></tr>}
            {data?.slice(0,20).map(r => (
              <tr key={r.id} className="hover:bg-gray-800/30">
                <td className="py-1.5 pr-3 text-gray-300 max-w-xs truncate">{r.name}</td>
                <td className="py-1.5 pr-3 text-gray-500">{r.pid}</td>
                <td className="py-1.5 pr-3 text-gray-400">{r.score}</td>
                <td className={`py-1.5 font-medium ${verdictColor(r.status)}`}>{r.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default function App() {
  const { data: summary, refetch } = useFetch("/api/summary", 10000)
  const [lastUpdate, setLastUpdate] = useState(new Date())
  useEffect(() => {
    const t = setInterval(() => setLastUpdate(new Date()), 10000)
    return () => clearInterval(t)
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 text-white p-4 md:p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="bg-blue-600/20 border border-blue-500/30 rounded-xl p-2.5">
          <Shield size={22} className="text-blue-400" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-white">A3 Security System</h1>
          <div className="flex items-center gap-2 text-xs text-gray-500">
            <Activity size={10} className="text-green-500" />
            <span>Live</span>
            <Clock size={10} />
            <span>Updated {lastUpdate.toLocaleTimeString()}</span>
          </div>
        </div>
        <button onClick={refetch} className="ml-auto p-2 rounded-lg border border-gray-700/50 hover:bg-gray-800/50 transition-colors">
          <RefreshCw size={14} className="text-gray-400" />
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
        <Stat label="Processes scanned" value={summary?.processes_scanned} color="text-blue-400" />
        <Stat label="Threats flagged"   value={summary?.processes_flagged} color="text-red-400" />
        <Stat label="Files sandboxed"   value={summary?.sandboxed}         color="text-purple-400" />
        <Stat label="Malicious found"   value={summary?.malicious}         color="text-red-500" />
        <Stat label="Network devices"   value={summary?.network_devices}   color="text-green-400"
              sub={`${summary?.high_risk_devices ?? 0} high risk`} />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <AlertFeed />
        <NetworkMap />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <SandboxTable />
        <AITable />
      </div>
      <div className="grid grid-cols-1 gap-4">
        <ProcessFeed />
      </div>
      <div className="mt-6 text-center text-xs text-gray-600">
        A3 Security System — all data stored locally — no cloud
      </div>
    </div>
  )
}