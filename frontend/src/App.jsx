import { useState, useEffect } from 'react';
import './App.css';

function App() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [visible, setVisible] = useState(true);

  useEffect(() => {
    const currentUrl = window.location.href;

    fetch('http://localhost:5000/predict_url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: currentUrl })
    })
      .then(res => res.json())
      .then(data => {
        setLoading(false);
        if (data.error) setError(data.error);
        else setResult(data);

        setTimeout(() => setVisible(false), 4000);
      })
      .catch(() => {
        setLoading(false);
        setError('PhishAlert unavailable');
        setTimeout(() => setVisible(false), 2000);
      });
  }, []);

  if (!visible) return null;

  let bg = 'bg-slate-900';
  let icon = '🔍';
  let text = 'text-white';

  if (result) {
    if (result.status === 'danger') {
      bg = 'bg-red-600';
      icon = '🚨';
    } else if (result.status === 'warning') {
      bg = 'bg-yellow-500';
      icon = '⚠️';
      text = 'text-black';
    } else {
      bg = 'bg-green-600';
      icon = '✅';
    }
  }

  return (
    <div
      style={{
        position: "fixed",
        top: "16px",
        right: "16px",
        zIndex: 2147483647,
        pointerEvents: "none"
      }}
    >
      <div
        style={{
          pointerEvents: "auto",
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "10px 14px",
          borderRadius: "10px",
          background:
            result?.status === "danger"
              ? "#dc2626"
              : result?.status === "warning"
                ? "#facc15"
                : result
                  ? "#16a34a"
                  : "#1f2937",
          color: result?.status === "warning" ? "#000" : "#fff",
          boxShadow: "0 8px 25px rgba(0,0,0,0.25)",
          maxWidth: "240px",
          fontFamily: "sans-serif",
          backdropFilter: "blur(6px)",
          border: "1px solid rgba(255,255,255,0.2)"
        }}
      >
        <span style={{ fontSize: "20px" }}>
          {loading ? "🔍" : result?.status === "danger" ? "🚨" : result?.status === "warning" ? "⚠️" : "✅"}
        </span>

        <div style={{ flex: 1, fontSize: "12px" }}>
          <div style={{ fontWeight: "bold" }}>PhishAlert</div>

          {loading ? (
            <div>Checking site...</div>
          ) : error ? (
            <div>{error}</div>
          ) : (
            <>
              <div style={{ fontWeight: "600" }}>{result.message}</div>
              <div style={{ opacity: 0.8 }}>Risk: {result.risk_percent}%</div>
            </>
          )}
        </div>

        <button
          onClick={() => setVisible(false)}
          style={{
            background: "transparent",
            border: "none",
            color: "inherit",
            cursor: "pointer",
            fontSize: "14px"
          }}
        >
          ✕
        </button>
      </div>
    </div>
  );
}

export default App;