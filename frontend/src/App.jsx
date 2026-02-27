import { useEffect, useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "";
const TOKEN_KEY = "admin_token";
const ROLE_KEY = "auth_role";

async function getJson(path, options = {}, token) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers
  });

  if (res.status === 401) {
    const text = await res.text();
    const err = new Error(text || "Unauthorized");
    err.status = 401;
    throw err;
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed: ${res.status}`);
  }

  return res.json();
}

async function uploadFile(path, file, typeValue, token) {
  const form = new FormData();
  form.append("file", file);
  form.append("type", typeValue);
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    body: form
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Upload failed: ${res.status}`);
  }
  return res.json();
}

const NAV_ITEMS = [
  { id: "overview", label: "Overview" },
  { id: "analyze", label: "Analyze" },
  { id: "lists", label: "Lists" },
  { id: "feedback", label: "Feedback" }
];

const PRODUCT_NAME = "S.H.I.E.L.D.";
const PRODUCT_TAGLINE = "Secure Heuristics & Intelligent Enforcement for Links + Dialogue";

function StatCard({ label, value, hint }) {
  return (
    <div className="stat-card">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint ? <div className="stat-hint">{hint}</div> : null}
    </div>
  );
}

function Bar({ label, value, max }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="bar-row">
      <div className="bar-label">{label}</div>
      <div className="bar-track">
        <div className="bar-fill" style={{ width: `${pct}%` }} />
      </div>
      <div className="bar-value">{value}</div>
    </div>
  );
}

function Pie({ allowed, flagged, blocked }) {
  const total = allowed + flagged + blocked || 1;
  const allowPct = Math.round((allowed / total) * 100);
  const flagPct = Math.round((flagged / total) * 100);
  const blockPct = 100 - allowPct - flagPct;
  const background = `conic-gradient(#7bcf9e 0 ${allowPct}%, #f2c879 ${allowPct}% ${allowPct + flagPct}%, #e27c72 ${allowPct + flagPct}% 100%)`;
  return (
    <div className="pie-wrap">
      <div className="pie" style={{ background }} />
      <div className="pie-legend">
        <div><span className="dot allow" /> Allow {allowPct}%</div>
        <div><span className="dot flag" /> Flag {flagPct}%</div>
        <div><span className="dot block" /> Block {blockPct}%</div>
      </div>
    </div>
  );
}

function Sparkline({ values = [] }) {
  if (!values.length) return null;
  const max = Math.max(...values, 1);
  const points = values.map((v, i) => `${i * 20},${40 - (v / max) * 40}`).join(" ");
  return (
    <svg className="spark" viewBox="0 0 120 40" preserveAspectRatio="none">
      <polyline points={points} fill="none" stroke="#e06b1f" strokeWidth="2" />
    </svg>
  );
}

function LineChart({ series = [], keys = [] }) {
  if (!series.length) return null;
  const width = 300;
  const height = 120;
  const max = Math.max(
    1,
    ...series.flatMap((d) => keys.map((k) => d[k] || 0))
  );

  return (
    <svg className="line-chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none">
      {keys.map((key, idx) => {
        const color = ["#7bcf9e", "#f2c879", "#e27c72"][idx % 3];
        const points = series.map((d, i) => {
          const x = (i / Math.max(series.length - 1, 1)) * (width - 10) + 5;
          const y = height - (d[key] / max) * (height - 20) - 10;
          return `${x},${y}`;
        }).join(" ");
        return <polyline key={key} points={points} fill="none" stroke={color} strokeWidth="2" />;
      })}
    </svg>
  );
}

export default function App() {
  const [token, setToken] = useState(() => localStorage.getItem(TOKEN_KEY));
  const [role, setRole] = useState(() => localStorage.getItem(ROLE_KEY) || "admin");
  const [stats, setStats] = useState(null);
  const [messages, setMessages] = useState([]);
  const [feedback, setFeedback] = useState([]);
  const [blockedSummary, setBlockedSummary] = useState({ by_reason: {}, by_source: {} });
  const [trainingSummary, setTrainingSummary] = useState(null);
  const [slackChannel, setSlackChannel] = useState("");
  const [slackStatus, setSlackStatus] = useState("");
  const [slackChannels, setSlackChannels] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [loading, setLoading] = useState({
    stats: false,
    messages: false,
    feedback: false,
    retrain: false,
    login: false,
    analyze: false
  });
  const [error, setError] = useState("");
  const [retrainStatus, setRetrainStatus] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [analyzeInput, setAnalyzeInput] = useState({
    message: "",
    sender: "",
    sender_type: "email",
    image_url: ""
  });
  const [analyzeResult, setAnalyzeResult] = useState(null);
  const [analyzeHistory, setAnalyzeHistory] = useState([]);
  const [feedbackStatus, setFeedbackStatus] = useState({});
  const [feedbackComments, setFeedbackComments] = useState({});

  const [trustedAdmin, setTrustedAdmin] = useState([]);
  const [trustedUser, setTrustedUser] = useState([]);
  const [blockedAdmin, setBlockedAdmin] = useState([]);
  const [blockedUser, setBlockedUser] = useState([]);

  const [trustedForm, setTrustedForm] = useState({ type: "domain", value: "", bulk: "", file: null });
  const [blockedForm, setBlockedForm] = useState({ type: "domain", value: "", bulk: "", file: null });

  const hasError = useMemo(() => error.trim().length > 0, [error]);
  const totalFeedback = stats?.total_feedback ?? 0;
  const phishingCount = stats?.phishing ?? 0;
  const legitCount = stats?.legit ?? 0;
  const totalMessages = stats?.total_messages ?? messages.length;
  const flaggedCount = stats?.flagged ?? messages.filter((m) => m.verdict === "FLAG").length;
  const blockedCount = stats?.blocked ?? messages.filter((m) => m.verdict === "BLOCK").length;
  const allowedCount = stats?.allowed ?? Math.max(totalMessages - blockedCount - flaggedCount, 0);

  const feedbackByMessage = useMemo(() => {
    const set = new Set();
    feedback.forEach((f) => set.add(f.message_id));
    return set;
  }, [feedback]);

  function clearAuth() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ROLE_KEY);
    setToken(null);
  }

  async function login(evt) {
    evt.preventDefault();
    setLoading((s) => ({ ...s, login: true }));
    setError("");
    try {
      const endpoint = role === "admin" ? "/v1/auth/login" : "/v1/user/auth/login";
      const data = await getJson(endpoint, {
        method: "POST",
        body: JSON.stringify({ email, password })
      });
      localStorage.setItem(TOKEN_KEY, data.token);
      localStorage.setItem(ROLE_KEY, role);
      setToken(data.token);
      setPassword("");
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading((s) => ({ ...s, login: false }));
    }
  }

  async function loadStats() {
    setLoading((s) => ({ ...s, stats: true }));
    try {
      const endpoint = role === "admin" ? "/v1/admin/stats" : "/v1/user/stats";
      const data = await getJson(endpoint, {}, token);
      setStats(data);
    } catch (err) {
      if (err.status === 401) {
        clearAuth();
        setError("Session expired. Please log in again.");
        return;
      }
      setError(err.message || "Failed to load stats");
    } finally {
      setLoading((s) => ({ ...s, stats: false }));
    }
  }

  async function loadAnalytics() {
    try {
      const endpoint = role === "admin" ? "/v1/admin/analytics" : "/v1/user/analytics";
      const data = await getJson(endpoint, {}, token);
      setAnalytics(data);
    } catch (err) {
      setError(err.message || "Failed to load analytics");
    }
  }

  async function loadMessages() {
    setLoading((s) => ({ ...s, messages: true }));
    try {
      const data = await getJson("/v1/admin/messages", {}, token);
      setMessages(Array.isArray(data) ? data : []);
    } catch (err) {
      if (err.status === 401) {
        clearAuth();
        setError("Session expired. Please log in again.");
        return;
      }
      setError(err.message || "Failed to load messages");
    } finally {
      setLoading((s) => ({ ...s, messages: false }));
    }
  }

  async function loadFeedback() {
    setLoading((s) => ({ ...s, feedback: true }));
    try {
      const data = await getJson("/v1/admin/feedback", {}, token);
      setFeedback(Array.isArray(data) ? data : []);
    } catch (err) {
      if (err.status === 401) {
        clearAuth();
        setError("Session expired. Please log in again.");
        return;
      }
      setError(err.message || "Failed to load feedback");
    } finally {
      setLoading((s) => ({ ...s, feedback: false }));
    }
  }

  async function loadBlockedSummary() {
    try {
      const endpoint = role === "admin" ? "/v1/admin/blocked-summary" : "/v1/user/blocked-summary";
      const data = await getJson(endpoint, {}, token);
      setBlockedSummary(data || { by_reason: {}, by_source: {} });
    } catch (err) {
      setError(err.message || "Failed to load blocked summary");
    }
  }

  async function loadTrainingSummary() {
    try {
      const data = await getJson("/v1/admin/training-summary", {}, token);
      setTrainingSummary(data);
    } catch (err) {
      setError(err.message || "Failed to load training summary");
    }
  }

  async function loadSlackChannel() {
    if (role !== "admin") return;
    try {
      const data = await getJson("/v1/admin/settings/slack-channel", {}, token);
      setSlackChannel(data?.channel || "");
    } catch (err) {
      setError(err.message || "Failed to load Slack channel");
    }
  }

  async function loadSlackChannels() {
    if (role !== "admin") return;
    try {
      const data = await getJson("/v1/admin/settings/slack-channels", {}, token);
      setSlackChannels(data?.channels || []);
    } catch (err) {
      setError(err.message || "Failed to load Slack channels");
    }
  }

  async function saveSlackChannel(evt) {
    evt.preventDefault();
    setSlackStatus("Saving...");
    try {
      const data = await getJson(
        "/v1/admin/settings/slack-channel",
        { method: "POST", body: JSON.stringify({ channel: slackChannel }) },
        token
      );
      setSlackChannel(data?.channel || "");
      setSlackStatus("Saved");
    } catch (err) {
      setSlackStatus("Error");
      setError(err.message || "Failed to save Slack channel");
    }
  }

  async function loadLists() {
    try {
      if (role === "admin") {
        const [aTrusted, aBlocked] = await Promise.all([
          getJson("/v1/admin/trusted", {}, token),
          getJson("/v1/admin/blocked", {}, token)
        ]);
        setTrustedAdmin(aTrusted || []);
        setBlockedAdmin(aBlocked || []);
        setTrustedUser([]);
        setBlockedUser([]);
      } else {
        const [uTrusted, uBlocked] = await Promise.all([
          getJson("/v1/user/trusted", {}, token),
          getJson("/v1/user/blocked", {}, token)
        ]);
        setTrustedAdmin([]);
        setTrustedUser(uTrusted?.user || uTrusted || []);
        setBlockedAdmin([]);
        setBlockedUser(uBlocked?.user || uBlocked || []);
      }
    } catch (err) {
      setError(err.message || "Failed to load lists");
    }
  }

  async function retrain() {
    setLoading((s) => ({ ...s, retrain: true }));
    setRetrainStatus("Retraining...");
    try {
      const data = await getJson("/v1/admin/retrain", { method: "POST" }, token);
      setRetrainStatus(data?.reason || data?.status || "Retrain finished");
      loadTrainingSummary();
    } catch (err) {
      if (err.status === 401) {
        clearAuth();
        setError("Session expired. Please log in again.");
        return;
      }
      setRetrainStatus(err.message || "Retrain failed");
      setError(err.message || "Retrain failed");
    } finally {
      setLoading((s) => ({ ...s, retrain: false }));
    }
  }

  async function analyzeMessage(evt) {
    evt.preventDefault();
    setLoading((s) => ({ ...s, analyze: true }));
    setError("");
    setAnalyzeResult(null);
    try {
      const data = await getJson(
        "/v1/analyze",
        {
          method: "POST",
          body: JSON.stringify({
            message: analyzeInput.message,
            sender: analyzeInput.sender || undefined,
            sender_type: analyzeInput.sender_type || undefined,
            image_url: analyzeInput.image_url || undefined
          })
        },
        token
      );
      const summary = {
        verdict: data.verdict,
        risk_score: data.risk_score,
        signals: data.signals || []
      };
      setAnalyzeResult(summary);
      setAnalyzeHistory((prev) => [{
        id: data.message_id,
        message: analyzeInput.message,
        verdict: data.verdict,
        risk_score: data.risk_score,
        created_at: new Date().toISOString()
      }, ...prev].slice(0, 8));
      setAnalyzeInput((prev) => ({ ...prev, message: "" }));
      loadMessages();
      loadBlockedSummary();
      loadAnalytics();
    } catch (err) {
      setError(err.message || "Analyze failed");
    } finally {
      setLoading((s) => ({ ...s, analyze: false }));
    }
  }

  async function giveFeedback(messageId, isPhishing) {
    setFeedbackStatus((s) => ({ ...s, [messageId]: "Saving..." }));
    const comment = feedbackComments[messageId] || "";
    try {
      await getJson(
        "/v1/feedback",
        {
          method: "POST",
          body: JSON.stringify({
            message_id: messageId,
            is_phishing: isPhishing ? 1 : 0,
            comment: comment || undefined
          })
        },
        token
      );
      setFeedbackStatus((s) => ({ ...s, [messageId]: "Saved" }));
      loadFeedback();
      loadStats();
      loadAnalytics();
    } catch (err) {
      setFeedbackStatus((s) => ({ ...s, [messageId]: "Error" }));
      setError(err.message || "Failed to save feedback");
    }
  }

  async function addTrusted(evt) {
    evt.preventDefault();
    const endpoint = role === "admin" ? "/v1/admin/trusted" : "/v1/user/trusted";
    await getJson(endpoint, {
      method: "POST",
      body: JSON.stringify({ value: trustedForm.value, type: trustedForm.type })
    }, token);
    setTrustedForm((s) => ({ ...s, value: "" }));
    loadLists();
  }

  async function addTrustedBulk() {
    const values = trustedForm.bulk.split(/\n|,/).map((v) => v.trim()).filter(Boolean);
    if (!values.length) return;
    const endpoint = role === "admin" ? "/v1/admin/trusted/bulk" : "/v1/user/trusted/bulk";
    await getJson(endpoint, {
      method: "POST",
      body: JSON.stringify({ values, type: trustedForm.type })
    }, token);
    setTrustedForm((s) => ({ ...s, bulk: "" }));
    loadLists();
  }

  async function addTrustedFile() {
    if (!trustedForm.file) return;
    const endpoint = role === "admin" ? "/v1/admin/trusted/upload" : "/v1/user/trusted/upload";
    await uploadFile(endpoint, trustedForm.file, trustedForm.type, token);
    setTrustedForm((s) => ({ ...s, file: null }));
    loadLists();
  }
  async function deleteTrusted(id, scope) {
    if (role !== "admin" && scope === "admin") return;
    const endpoint = scope === "admin" ? `/v1/admin/trusted/${id}` : `/v1/user/trusted/${id}`;
    await getJson(endpoint, { method: "DELETE" }, token);
    loadLists();
  }

  async function addBlocked(evt) {
    evt.preventDefault();
    const endpoint = role === "admin" ? "/v1/admin/blocked" : "/v1/user/blocked";
    await getJson(endpoint, {
      method: "POST",
      body: JSON.stringify({ value: blockedForm.value, type: blockedForm.type })
    }, token);
    setBlockedForm((s) => ({ ...s, value: "" }));
    loadLists();
  }

  async function addBlockedBulk() {
    const values = blockedForm.bulk.split(/\n|,/).map((v) => v.trim()).filter(Boolean);
    if (!values.length) return;
    const endpoint = role === "admin" ? "/v1/admin/blocked/bulk" : "/v1/user/blocked/bulk";
    await getJson(endpoint, {
      method: "POST",
      body: JSON.stringify({ values, type: blockedForm.type })
    }, token);
    setBlockedForm((s) => ({ ...s, bulk: "" }));
    loadLists();
  }

  async function addBlockedFile() {
    if (!blockedForm.file) return;
    const endpoint = role === "admin" ? "/v1/admin/blocked/upload" : "/v1/user/blocked/upload";
    await uploadFile(endpoint, blockedForm.file, blockedForm.type, token);
    setBlockedForm((s) => ({ ...s, file: null }));
    loadLists();
  }
  async function deleteBlocked(id, scope) {
    if (role !== "admin" && scope === "admin") return;
    const endpoint = scope === "admin" ? `/v1/admin/blocked/${id}` : `/v1/user/blocked/${id}`;
    await getJson(endpoint, { method: "DELETE" }, token);
    loadLists();
  }

  useEffect(() => {
    if (!token) {
      return;
    }
    loadStats();
    loadBlockedSummary();
    loadAnalytics();
    if (role === "admin") {
      loadMessages();
      loadFeedback();
      loadTrainingSummary();
      loadSlackChannel();
      loadSlackChannels();
    }
    loadLists();
  }, [token, role]);

  if (!token) {
    return (
      <div className="auth-shell">
        <div className="auth-panel">
          <div className="auth-brand">
            <div className="eyebrow">Admin Access</div>
            <h1>{PRODUCT_NAME}</h1>
            <p>{PRODUCT_TAGLINE}</p>
          </div>
          {hasError ? <div className="banner">{error}</div> : null}
          <form className="auth-form" onSubmit={login}>
            <label>
              Role
              <select value={role} onChange={(e) => setRole(e.target.value)}>
                <option value="admin">Admin</option>
                <option value="user">User</option>
              </select>
            </label>
            <label>
              Email
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@example.com"
                required
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
              />
            </label>
            <button className="refresh" type="submit" disabled={loading.login}>
              {loading.login ? "Signing in..." : "Sign in"}
            </button>
          </form>
        </div>
        <div className="auth-visual">
          <div className="orb" />
          <div className="grid" />
          <div className="auth-copy">
            <h2>{PRODUCT_NAME}</h2>
            <p>{PRODUCT_TAGLINE}</p>
          </div>
        </div>
      </div>
    );
  }

  const topReasons = Object.entries(analytics?.block_reasons || {}).slice(0, 5);
  const topSources = Object.entries(analytics?.block_sources || {}).slice(0, 5);
  const riskHistogram = analytics?.risk_histogram || {};
  const tldDistribution = Object.entries(analytics?.tld_distribution || {}).slice(0, 6);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="brand">{PRODUCT_NAME}</div>
          <div className="brand-sub">{PRODUCT_TAGLINE}</div>
        </div>
        <nav className="nav">
          {NAV_ITEMS.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${activeTab === item.id ? "active" : ""}`}
              onClick={() => setActiveTab(item.id)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <button className="ghost logout" onClick={clearAuth}>
            Log out
          </button>
          <button
            className="refresh"
            onClick={() => {
              setError("");
              loadStats();
              loadMessages();
              loadFeedback();
              loadBlockedSummary();
              loadTrainingSummary();
              loadAnalytics();
              loadLists();
            }}
          >
            Refresh
          </button>
        </div>
      </aside>

      <main className="content">
        <header className="page-header">
          <div>
            <div className="eyebrow">Admin Console</div>
            <h1>IM Phishing Detection</h1>
            <p>Monitor risk, review messages, and retrain models.</p>
          </div>
        </header>

        {hasError ? <div className="banner">{error}</div> : null}

        {activeTab === "overview" ? (
          <>
            {role !== "admin" ? (
              <section className="card">
                <div className="card-header">
                  <h2>User View</h2>
                  <span className="muted">Analytics are visible to admins only.</span>
                </div>
                <p>Switch to the Lists tab to manage your trusted and blocked entries.</p>
              </section>
            ) : null}
            <section className="stats-grid">
              {loading.stats ? (
                <>
                  <div className="stat-card skeleton" />
                  <div className="stat-card skeleton" />
                  <div className="stat-card skeleton" />
                  <div className="stat-card skeleton" />
                </>
              ) : (
                <>
                  <StatCard label="Total Feedback" value={totalFeedback} hint="User-labeled signals" />
                  <StatCard label="Phishing" value={phishingCount} hint="Confirmed phishing" />
                  <StatCard label="Legit" value={legitCount} hint="Confirmed legitimate" />
                  <StatCard label="Messages" value={totalMessages} hint="Recent messages" />
                </>
              )}
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Status</h2>
                <span className="muted">System health snapshot</span>
              </div>
              <div className="status-row">
                <div className="status-pill">ML: Active</div>
                <div className="status-pill">NLP: Active</div>
                <div className="status-pill">CV: Active</div>
                <div className="status-pill">DB: Connected</div>
              </div>
            </section>

            {role === "admin" ? (
              <section className="card">
                <div className="card-header">
                  <h2>Slack Alerts</h2>
                  <span className="muted">Default channel for flag/block alerts</span>
                </div>
                <form className="list-form" onSubmit={saveSlackChannel}>
                  <div className="scope-pill">Admin config</div>
                  <div className="lock-note">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M7 10V8a5 5 0 0 1 10 0v2h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" />
                    </svg>
                    <span>Admin-only edits</span>
                  </div>
                  <select
                    value={slackChannel}
                    onChange={(e) => setSlackChannel(e.target.value)}
                  >
                    <option value="">Select Slack channel</option>
                    {slackChannels.map((ch) => (
                      <option key={ch.id} value={ch.id}>
                        #{ch.name} ({ch.id})
                      </option>
                    ))}
                  </select>
                  <button className="refresh" type="submit">Save</button>
                </form>
                <div className="muted">
                  If your channel isn’t listed, type its ID manually in the box below.
                </div>
                <div className="manual-channel">
                  <input
                    value={slackChannel}
                    onChange={(e) => setSlackChannel(e.target.value)}
                    placeholder="Manual channel ID (e.g. C1234567890)"
                  />
                </div>
                <div className="status-note">{slackStatus}</div>
              </section>
            ) : null}

            <section className="grid-two">
              <section className="card">
                <div className="card-header">
                  <h2>Verdict Mix</h2>
                  <span className="muted">Allow vs Flag vs Block</span>
                </div>
                {loading.stats ? (
                  <div className="chart-skeleton" />
                ) : (
                  <Pie allowed={allowedCount} flagged={flaggedCount} blocked={blockedCount} />
                )}
              </section>

              <section className="card">
                <div className="card-header">
                  <h2>Verdict Trend</h2>
                  <span className="muted">7-day trend</span>
                </div>
                {analytics?.verdict_trend ? (
                  <LineChart series={analytics.verdict_trend} keys={["ALLOW", "FLAG", "BLOCK"]} />
                ) : (
                  <div className="chart-skeleton" />
                )}
              </section>
            </section>

            <section className="grid-two">
              <section className="card">
                <div className="card-header">
                  <h2>Feedback Breakdown</h2>
                  <span className="muted">Phishing vs Legit labels</span>
                </div>
                {loading.stats ? (
                  <div className="chart-skeleton tall" />
                ) : (
                  <div className="bar-stack">
                    <Bar label="Phishing" value={phishingCount} max={totalFeedback || 1} />
                    <Bar label="Legit" value={legitCount} max={totalFeedback || 1} />
                  </div>
                )}
              </section>

              <section className="card">
                <div className="card-header">
                  <h2>Feedback Trend</h2>
                  <span className="muted">7-day labels</span>
                </div>
                {analytics?.feedback_trend ? (
                  <LineChart series={analytics.feedback_trend} keys={["phishing", "legit"]} />
                ) : (
                  <div className="chart-skeleton" />
                )}
              </section>
            </section>

            <section className="grid-two">
              <section className="card">
                <div className="card-header">
                  <h2>Risk Distribution</h2>
                  <span className="muted">Histogram</span>
                </div>
                <div className="bar-stack">
                  {Object.entries(riskHistogram).map(([bucket, count]) => (
                    <Bar key={bucket} label={bucket} value={count} max={Math.max(...Object.values(riskHistogram || {0:1}), 1)} />
                  ))}
                </div>
              </section>

              <section className="card">
                <div className="card-header">
                  <h2>Top TLDs</h2>
                  <span className="muted">Most common link domains</span>
                </div>
                <ul className="summary-list">
                  {tldDistribution.length ? tldDistribution.map(([tld, count]) => (
                    <li key={tld}>{tld}: {count}</li>
                  )) : <li>No links yet.</li>}
                </ul>
              </section>
            </section>

            <section className="grid-two">
              <section className="card">
                <div className="card-header">
                  <h2>Top Block Reasons</h2>
                  <span className="muted">Most common block triggers</span>
                </div>
                <ul className="summary-list">
                  {topReasons.length ? topReasons.map(([reason, count]) => (
                    <li key={reason}>{reason}: {count}</li>
                  )) : <li>No blocks yet.</li>}
                </ul>
              </section>

              <section className="card">
                <div className="card-header">
                  <h2>Top Block Sources</h2>
                  <span className="muted">Sender, domain, URL sources</span>
                </div>
                <ul className="summary-list">
                  {topSources.length ? topSources.map(([source, count]) => (
                    <li key={source}>{source}: {count}</li>
                  )) : <li>No blocks yet.</li>}
                </ul>
              </section>
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Message Trend</h2>
                <span className="muted">Recent activity (sparkline)</span>
              </div>
              {loading.messages ? (
                <div className="chart-skeleton short" />
              ) : (
                <Sparkline values={messages.slice(0, 6).map((m) => m.risk_score ?? 0)} />
              )}
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Blocked Types & Sources</h2>
                <span className="muted">Why and from where blocks happen</span>
              </div>
              <div className="summary-grid">
                <div>
                  <h3>Reasons</h3>
                  {Object.keys(blockedSummary.by_reason || {}).length ? (
                    <ul className="summary-list">
                      {Object.entries(blockedSummary.by_reason).map(([reason, count]) => (
                        <li key={reason}>{reason}: {count}</li>
                      ))}
                    </ul>
                  ) : (
                    <div className="muted">No blocks yet.</div>
                  )}
                </div>
                <div>
                  <h3>Sources</h3>
                  {Object.keys(blockedSummary.by_source || {}).length ? (
                    <ul className="summary-list">
                      {Object.entries(blockedSummary.by_source).map(([source, count]) => (
                        <li key={source}>{source}: {count}</li>
                      ))}
                    </ul>
                  ) : (
                    <div className="muted">No sources yet.</div>
                  )}
                </div>
              </div>
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Training Summary</h2>
                <span className="muted">Latest retraining dataset usage</span>
              </div>
              {trainingSummary && trainingSummary.model_path ? (
                <div className="summary-grid">
                  <div><strong>Total rows:</strong> {trainingSummary.rows_total}</div>
                  <div><strong>Public rows:</strong> {trainingSummary.rows_public}</div>
                  <div><strong>Feedback rows:</strong> {trainingSummary.rows_feedback}</div>
                  <div><strong>Model:</strong> {trainingSummary.model_path}</div>
                </div>
              ) : (
                <div className="muted">No retraining run yet.</div>
              )}
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Retrain Model</h2>
                <span className="muted">Triggers the training pipeline</span>
              </div>
              <div className="retrain-row">
                <button className="danger" onClick={retrain} disabled={loading.retrain}>
                  {loading.retrain ? "Retraining..." : "Trigger Retrain"}
                </button>
                <div className="status-note">{retrainStatus}</div>
              </div>
            </section>
          </>
        ) : null}

        {activeTab === "analyze" ? (
          <>
            <section className="card">
              <div className="card-header">
                <h2>Analyze Message</h2>
                <span className="muted">Quickly score a single message</span>
              </div>
              <form className="analyze-form" onSubmit={analyzeMessage}>
                <label className="full">
                  Message
                  <textarea
                    rows={3}
                    value={analyzeInput.message}
                    onChange={(e) => setAnalyzeInput((s) => ({ ...s, message: e.target.value }))}
                    placeholder="Paste the message to analyze"
                    required
                  />
                </label>
                <label>
                  Sender type
                  <select
                    value={analyzeInput.sender_type}
                    onChange={(e) => setAnalyzeInput((s) => ({ ...s, sender_type: e.target.value }))}
                  >
                    <option value="email">Email</option>
                    <option value="phone">Phone</option>
                    <option value="domain">Domain</option>
                  </select>
                </label>
                <label>
                  Sender (optional)
                  <input
                    type="text"
                    value={analyzeInput.sender}
                    onChange={(e) => setAnalyzeInput((s) => ({ ...s, sender: e.target.value }))}
                    placeholder="sender@company.com"
                  />
                </label>
                <label>
                  Image URL (optional)
                  <input
                    type="text"
                    value={analyzeInput.image_url}
                    onChange={(e) => setAnalyzeInput((s) => ({ ...s, image_url: e.target.value }))}
                    placeholder="https://..."
                  />
                </label>
                <button className="refresh" type="submit" disabled={loading.analyze}>
                  {loading.analyze ? "Analyzing..." : "Analyze"}
                </button>
              </form>
              {analyzeResult ? (
                <div className={`result-card ${analyzeResult.verdict?.toLowerCase() || ""}`}>
                  <div className="result-title">Verdict: {analyzeResult.verdict || "-"}</div>
                  <div className="result-meta">Risk score: {analyzeResult.risk_score ?? "-"}</div>
                  {analyzeResult.signals?.length ? (
                    <div className="result-signals">
                      {analyzeResult.signals.map((sig) => (
                        <span key={sig} className="chip">{sig}</span>
                      ))}
                    </div>
                  ) : (
                    <div className="muted">No signals detected.</div>
                  )}
                </div>
              ) : null}

              {analyzeHistory.length ? (
                <div className="history">
                  <div className="history-title">Recent analyses</div>
                  <div className="history-grid">
                    {analyzeHistory.map((item) => (
                      <div key={`${item.id}-${item.created_at}`} className="history-card">
                        <div className="history-meta">
                          <span>#{item.id}</span>
                          <span className={`pill ${item.verdict?.toLowerCase() || ""}`}>
                            {item.verdict || "-"}
                          </span>
                        </div>
                        <div className="history-message">{item.message}</div>
                        <div className="muted">Risk: {item.risk_score ?? "-"}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Messages</h2>
                <span className="muted">Latest flagged or scored items</span>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>ID</th>
                      <th>Content</th>
                      <th>Risk</th>
                      <th>Verdict</th>
                      <th>Feedback</th>
                    </tr>
                  </thead>
                  <tbody>
                    {messages.map((m) => {
                      const hasFeedback = feedbackByMessage.has(m.id);
                      return (
                        <tr key={m.id}>
                          <td>{m.id}</td>
                          <td>{m.content}</td>
                          <td>{m.risk_score ?? "-"}</td>
                          <td>
                            <span className={`verdict-box ${m.verdict?.toLowerCase() || ""}`}>
                              {m.verdict ?? "-"}
                            </span>
                          </td>
                          <td>
                            <div className="feedback-actions">
                              <input
                                className="feedback-input"
                                type="text"
                                value={feedbackComments[m.id] || ""}
                                onChange={(e) =>
                                  setFeedbackComments((s) => ({
                                    ...s,
                                    [m.id]: e.target.value
                                  }))
                                }
                                placeholder="Add comment (optional)"
                                disabled={hasFeedback}
                              />
                              <button
                                className="chip danger"
                                type="button"
                                onClick={() => giveFeedback(m.id, true)}
                                disabled={hasFeedback}
                              >
                                Phishing
                              </button>
                              <button
                                className="chip"
                                type="button"
                                onClick={() => giveFeedback(m.id, false)}
                                disabled={hasFeedback}
                              >
                                Legit
                              </button>
                              <span className="muted">{hasFeedback ? "Locked" : feedbackStatus[m.id] || ""}</span>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                    {messages.length === 0 ? (
                      <tr>
                        <td colSpan={5} className="muted">No messages found.</td>
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        ) : null}

        {activeTab === "lists" ? (
          <>
            <section className="card">
              <div className="card-header">
                <h2>Trusted Senders</h2>
                <span className="muted">Admin and user allowlists</span>
              </div>
              <form className="list-form" onSubmit={addTrusted}>
                <div className="scope-pill">{role === "admin" ? "Admin list" : "User list"}</div>
                <div className="lock-note">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M7 10V8a5 5 0 0 1 10 0v2h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" />
                  </svg>
                  <span>{role === "admin" ? "Admin-only edits" : "User-only edits"}</span>
                </div>
                <select
                  value={trustedForm.type}
                  onChange={(e) => setTrustedForm((s) => ({ ...s, type: e.target.value }))}
                >
                  <option value="domain">Domain</option>
                  <option value="email">Email</option>
                  <option value="phone">Phone</option>
                </select>
                <input
                  value={trustedForm.value}
                  onChange={(e) => setTrustedForm((s) => ({ ...s, value: e.target.value }))}
                  placeholder="Add trusted domain / email / phone"
                  required
                />
                <button className="refresh" type="submit">Add</button>
              </form>
              <div className="bulk">
                <textarea
                  placeholder="Bulk add (comma or newline separated)"
                  value={trustedForm.bulk}
                  onChange={(e) => setTrustedForm((s) => ({ ...s, bulk: e.target.value }))}
                />
                <div className="bulk-actions">
                  <button className="ghost" type="button" onClick={addTrustedBulk}>Bulk add</button>
                  <label className="file-btn">
                    Upload CSV/XLSX
                    <input
                      type="file"
                      accept=".csv,.xlsx,.xls"
                      onChange={(e) => setTrustedForm((s) => ({ ...s, file: e.target.files?.[0] || null }))}
                    />
                  </label>
                  <button className="refresh" type="button" onClick={addTrustedFile} disabled={!trustedForm.file}>
                    Import
                  </button>
                </div>
              </div>
              <div className="summary-grid">
                {role === "admin" ? (
                  <div>
                    <h3>Admin Trusted</h3>
                    <ul className="summary-list">
                      {trustedAdmin.map((item) => (
                        <li key={item.id}>
                          <span>{item.type}: {item.value}</span>
                          <button className="link" onClick={() => deleteTrusted(item.id, "admin")}>Remove</button>
                        </li>
                      ))}
                      {trustedAdmin.length === 0 ? (
                        <li className="muted">No admin trusted entries.</li>
                      ) : null}
                    </ul>
                  </div>
                ) : (
                  <div>
                    <h3>User Trusted</h3>
                    <ul className="summary-list">
                      {trustedUser.map((item) => (
                        <li key={item.id}>
                          <span>{item.type}: {item.value}</span>
                          <button className="link" onClick={() => deleteTrusted(item.id, "user")}>Remove</button>
                        </li>
                      ))}
                      {trustedUser.length === 0 ? (
                        <li className="muted">No user trusted entries.</li>
                      ) : null}
                    </ul>
                  </div>
                )}
              </div>
            </section>

            <section className="card">
              <div className="card-header">
                <h2>Blocked Entities</h2>
                <span className="muted">Admin blocks override user blocks</span>
              </div>
              <form className="list-form" onSubmit={addBlocked}>
                <div className="scope-pill">{role === "admin" ? "Admin list" : "User list"}</div>
                <div className="lock-note">
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M7 10V8a5 5 0 0 1 10 0v2h1a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2h1Zm2 0h6V8a3 3 0 0 0-6 0v2Z" />
                  </svg>
                  <span>{role === "admin" ? "Admin-only edits" : "User-only edits"}</span>
                </div>
                <select
                  value={blockedForm.type}
                  onChange={(e) => setBlockedForm((s) => ({ ...s, type: e.target.value }))}
                >
                  <option value="domain">Domain</option>
                  <option value="url">URL</option>
                  <option value="email">Email</option>
                  <option value="phone">Phone</option>
                </select>
                <input
                  value={blockedForm.value}
                  onChange={(e) => setBlockedForm((s) => ({ ...s, value: e.target.value }))}
                  placeholder="Add blocked domain / url / email / phone"
                  required
                />
                <button className="refresh" type="submit">Add</button>
              </form>
              <div className="bulk">
                <textarea
                  placeholder="Bulk add (comma or newline separated)"
                  value={blockedForm.bulk}
                  onChange={(e) => setBlockedForm((s) => ({ ...s, bulk: e.target.value }))}
                />
                <div className="bulk-actions">
                  <button className="ghost" type="button" onClick={addBlockedBulk}>Bulk add</button>
                  <label className="file-btn">
                    Upload CSV/XLSX
                    <input
                      type="file"
                      accept=".csv,.xlsx,.xls"
                      onChange={(e) => setBlockedForm((s) => ({ ...s, file: e.target.files?.[0] || null }))}
                    />
                  </label>
                  <button className="refresh" type="button" onClick={addBlockedFile} disabled={!blockedForm.file}>
                    Import
                  </button>
                </div>
              </div>
              <div className="summary-grid">
                {role === "admin" ? (
                  <div>
                    <h3>Admin Blocked</h3>
                    <ul className="summary-list">
                      {blockedAdmin.map((item) => (
                        <li key={item.id}>
                          <span>{item.type}: {item.value}</span>
                          <button className="link" onClick={() => deleteBlocked(item.id, "admin")}>Remove</button>
                        </li>
                      ))}
                      {blockedAdmin.length === 0 ? (
                        <li className="muted">No admin blocked entries.</li>
                      ) : null}
                    </ul>
                  </div>
                ) : (
                  <div>
                    <h3>User Blocked</h3>
                    <ul className="summary-list">
                      {blockedUser.map((item) => (
                        <li key={item.id}>
                          <span>{item.type}: {item.value}</span>
                          <button className="link" onClick={() => deleteBlocked(item.id, "user")}>Remove</button>
                        </li>
                      ))}
                      {blockedUser.length === 0 ? (
                        <li className="muted">No user blocked entries.</li>
                      ) : null}
                    </ul>
                  </div>
                )}
              </div>
            </section>
          </>
        ) : null}

        {activeTab === "feedback" ? (
          <section className="card">
            <div className="card-header">
              <h2>Feedback</h2>
              <span className="muted">Reviewer notes</span>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Message ID</th>
                    <th>Phishing</th>
                    <th>Comment</th>
                  </tr>
                </thead>
                <tbody>
                  {feedback.map((f) => (
                    <tr key={f.id}>
                      <td>{f.id}</td>
                      <td>{f.message_id}</td>
                      <td>{String(f.is_phishing)}</td>
                      <td>{f.comment ?? ""}</td>
                    </tr>
                  ))}
                  {feedback.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="muted">No feedback found.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </section>
        ) : null}
      </main>
    </div>
  );
}
