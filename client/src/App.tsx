import { useEffect, useState } from "react";
import { api, AppStatus } from "./api";

export default function App() {
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [ip, setIp] = useState<string>("…");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [url, setUrl] = useState("");

  const refreshIp = () => api.publicIp().then(setIp).catch(() => setIp("unknown"));

  useEffect(() => {
    api.status().then((s) => {
      setStatus(s);
      if (s.has_subscription && s.servers.length === 0) {
        api.refreshServers().then(setStatus).catch((e) => setError(String(e)));
      }
    });
    refreshIp();
    const t = setInterval(() => api.status().then(setStatus), 3000);
    return () => clearInterval(t);
  }, []);

  const call = async (fn: () => Promise<AppStatus | void>) => {
    setBusy(true);
    setError(null);
    try {
      const s = await fn();
      if (s) setStatus(s);
      refreshIp();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (!status) return <div className="screen center">Loading…</div>;

  if (!status.has_subscription) {
    return (
      <div className="screen center">
        <h1>Chatte VPN</h1>
        <p className="muted">Paste your subscription URL to get started.</p>
        <form
          className="sub-form"
          onSubmit={(e) => {
            e.preventDefault();
            call(() => api.setSubscription(url));
          }}
        >
          <input
            type="url"
            required
            placeholder="https://api.example.com/v1/subscription/…"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button type="submit" disabled={busy || !url}>
            {busy ? "Checking…" : "Add subscription"}
          </button>
        </form>
        {error && <p className="error">{error}</p>}
      </div>
    );
  }

  return (
    <div className="screen">
      <header>
        <h1>Chatte VPN</h1>
        <div className={`badge ${status.connected ? "on" : "off"}`}>
          {status.connected ? "Connected" : "Disconnected"}
        </div>
      </header>

      <div className="info-row">
        <span className="muted">Public IP</span>
        <span>{ip}</span>
      </div>
      {status.expires && (
        <div className="info-row">
          <span className="muted">Expires</span>
          <span>{new Date(status.expires).toLocaleDateString()}</span>
        </div>
      )}

      <div className="list-head">
        <span>Servers</span>
        <button className="link" disabled={busy} onClick={() => call(api.refreshServers)}>
          Refresh
        </button>
      </div>

      <ul className="servers">
        {status.servers.map((s) => {
          const active = status.connected && status.connected_server === s.id;
          return (
            <li key={s.id} className={active ? "active" : ""}>
              <div>
                <div className="name">{s.name}</div>
                <div className="muted small">
                  {s.city ? `${s.city}, ` : ""}
                  {s.country} · {s.protocol}
                </div>
              </div>
              <button
                disabled={busy}
                className={active ? "danger" : "primary"}
                onClick={() => call(() => (active ? api.disconnect() : api.connect(s.id)))}
              >
                {active ? "Disconnect" : "Connect"}
              </button>
            </li>
          );
        })}
        {status.servers.length === 0 && <li className="muted">No servers in subscription.</li>}
      </ul>

      {error && <p className="error">{error}</p>}

      <footer>
        <button className="link" disabled={busy} onClick={() => call(api.forgetSubscription)}>
          Remove subscription
        </button>
      </footer>
    </div>
  );
}
