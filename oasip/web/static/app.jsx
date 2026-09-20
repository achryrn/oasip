const { useState, useEffect } = React;
const { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
        PieChart, Pie, Cell, LineChart, Line, CartesianGrid, Legend,
        AreaChart, Area } = Recharts;

function App() {
  const [scans, setScans] = useState([]);
  const [sel, setSel] = useState('');
  const [data, setData] = useState(null);
  const [tab, setTab] = useState('overview');
  const [form, setForm] = useState({ target: '', org: '', modules: 'all', authorized: false });

  useEffect(() => {
    fetch('/api/scans').then(r => r.json()).then(list => {
      setScans(list);
      if (list.length && !sel) setSel(String(list[0].id));
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!sel) return;
    fetch('/api/scan/' + sel + '/all').then(r => r.json()).then(setData).catch(() => {});
    const t = setInterval(() => {
      fetch('/api/scan/' + sel + '/all').then(r => r.json())
        .then(d => { setData(d); if (d.status === 'done' || d.status === 'failed' || d.status === 'partial') clearInterval(t); })
        .catch(() => {});
    }, 4000);
    return () => clearInterval(t);
  }, [sel]);

  const startScan = () => {
    fetch('/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: form.target, org_name: form.org || null,
        modules: form.modules === 'all' ? null : form.modules.split(','), authorized: form.authorized })
    }).then(r => r.json()).then(() => {
      setTimeout(() => fetch('/api/scans').then(r => r.json()).then(list => {
        setScans(list); if (list.length) setSel(String(list[0].id));
      }), 800);
    });
  };

  return (
    <div className="wrap">
      <header>
        <h1>OASIP &mdash; Attack Surface Intelligence</h1>
        <select value={sel} onChange={e => setSel(e.target.value)}>
          {scans.map(s => <option key={s.id} value={s.id}>
            #{s.id} {s.target} ({s.status}{s.overall_score != null ? ', score ' + s.overall_score : ''})</option>)}
        </select>
        <span className="muted">Live refresh every 4s</span>
      </header>

      <div className="card">
        <h2>New scan</h2>
        <div className="row">
          <input placeholder="target domain" value={form.target} onChange={e => setForm({ ...form, target: e.target.value })} />
          <input placeholder="org name (optional)" value={form.org} onChange={e => setForm({ ...form, org: e.target.value })} />
          <input placeholder="modules (all, dns,ct,...)" value={form.modules} onChange={e => setForm({ ...form, modules: e.target.value })} />
          <label><input type="checkbox" checked={form.authorized} onChange={e => setForm({ ...form, authorized: e.target.checked })} /> I am authorized to test this target</label>
          <button onClick={startScan}>Start scan</button>
        </div>
      </div>

      {!data ? <div className="card muted">No scan selected or still loading&hellip;</div> : (
        <div>
          <div className="grid">
            <Kpi label="Overall risk" value={data.overall_score != null ? data.overall_score : '-'} />
            <Kpi label="Hosts" value={data.hosts ? data.hosts.length : 0} />
            <Kpi label="IPs" value={data.ips ? data.ips.length : 0} />
            <Kpi label="Findings" value={data.findings ? data.findings.length : 0} />
            <Kpi label="Certs" value={data.certs ? data.certs.length : 0} />
            <Kpi label="Takeovers" value={data.takeovers ? data.takeovers.length : 0} />
          </div>

          <div className="tab">
            {['overview','assets','findings','breaches','repos','cves','certs','takeovers','people'].map(t =>
              <button key={t} className={tab === t ? 'on' : ''} onClick={() => setTab(t)}>{t}</button>)}
          </div>

          {tab === 'overview' && <Overview data={data} />}
          {tab === 'assets' && <Assets data={data} />}
          {tab === 'findings' && <Findings data={data} />}
          {tab === 'breaches' && <Breaches data={data} />}
          {tab === 'repos' && <Repos data={data} />}
          {tab === 'cves' && <Cves data={data} />}
          {tab === 'certs' && <Certs data={data} />}
          {tab === 'takeovers' && <Takeovers data={data} />}
          {tab === 'people' && <People data={data} />}
        </div>
      )}
    </div>
  );
}

function Kpi({ label, value }) {
  return <div className="kpi"><div className="v">{value}</div><div className="l">{label}</div></div>;
}

function ScoreBadge({ score }) {
  const cls = score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'medium' : 'low';
  return <span className={'badge b-' + cls}>{score}</span>;
}

function SeveBadge({ sev }) {
  return <span className={'badge b-' + (sev || 'info').toLowerCase()}>{sev || 'info'}</span>;
}

function Overview({ data }) {
  const hmap = Object.entries(data.heatmap || {}).map(([k, v]) => ({ bucket: k, count: v }));
  const techCounts = {};
  (data.techs || []).forEach(t => { techCounts[t.name] = (techCounts[t.name] || 0) + 1; });
  const pie = Object.entries(techCounts).map(([name, value]) => ({ name, value })).slice(0, 10);
  const COLORS = ['#3a6ea5','#e37400','#8a6d00','#377e3f','#b3261e','#6a4fa3','#c2407a','#1f8a8c','#7c8798','#4a6f28'];
  return (
    <div>
      <div className="card"><h2>Risk heatmap &mdash; score distribution across assets</h2>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={hmap}><CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="bucket" /><YAxis allowDecimals={false} />
            <Tooltip /><Bar dataKey="count" fill="#3a6ea5" /></BarChart>
        </ResponsiveContainer>
      </div>
      <div className="card"><h2>Technology distribution</h2>
        {pie.length ? <ResponsiveContainer width="100%" height={240}>
          <PieChart><Pie data={pie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
            {pie.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Pie><Tooltip /><Legend /></PieChart>
        </ResponsiveContainer> : <div className="muted">None detected (run fingerprint module with public reachable hosts)</div>}
      </div>
      <div className="card"><h2>Latest findings</h2>
        <table><tbody>{(data.findings || []).slice(0, 20).map(f =>
          <tr key={f.id}><td><SeveBadge sev={f.severity} /></td><td>{f.title}</td><td className="muted">{f.asset || ''}</td></tr>)}
        </tbody></table>
      </div>
    </div>
  );
}

function Assets({ data }) {
  return (
    <div className="card"><h2>Asset inventory</h2>
      <table><thead><tr><th>Hostname</th><th>IPs</th><th>ASN</th><th>HTTP</th><th>Server</th><th>DMARC</th><th>Score</th></tr></thead>
      <tbody>{(data.hosts || []).map(h =>
        <tr key={h.hostname}><td><code>{h.hostname}</code></td>
        <td>{(h.ips || []).slice(0, 6).join(', ')}</td><td>{h.asn || ''}</td>
        <td>{h.http_status || ''}</td><td>{h.server_header || ''}</td>
        <td>{h.dmarc ? <SeveBadge sev={h.dmarc === 'none' ? 'medium' : 'low'} /> : ''}</td>
        <td><ScoreBadge score={h.score} /></td></tr>)}
      </tbody></table>
    </div>
  );
}

function Findings({ data }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  (data.findings || []).forEach(f => { if (counts[f.severity] !== undefined) counts[f.severity]++; });
  return (
    <div>
      <div className="grid">
        {Object.entries(counts).map(([k, v]) => <Kpi key={k} label={k} value={v} />)}
      </div>
      <div className="card"><table><thead><tr><th>Severity</th><th>Kind</th><th>Title</th><th>Asset</th></tr></thead>
        <tbody>{(data.findings || []).map(f =>
          <tr key={f.id}><td><SeveBadge sev={f.severity} /></td><td>{f.kind}</td><td>{f.title}</td><td>{f.asset || ''}</td></tr>)}
        </tbody></table></div>
    </div>
  );
}

function Breaches({ data }) {
  return (
    <div className="card"><h2>Breach exposure summary</h2>
      <table><thead><tr><th>Subject</th><th>Breach</th><th>Exposure</th><th>Pwned</th><th>Date</th></tr></thead>
      <tbody>{(data.breaches || []).map((b, i) =>
        <tr key={i}><td>{b.subject_name}</td><td>{b.breach_name}</td>
        <td><span className={'badge b-' + (b.pw_exposure || 'unknown')}>{b.pw_exposure || 'unknown'}</span></td>
        <td>{b.pwn_count || ''}</td><td>{b.breach_date || b.added_date || ''}</td></tr>)}
      </tbody></table>
    </div>
  );
}

function Repos({ data }) {
  return (
    <div className="card"><h2>Repository findings</h2>
      <table><thead><tr><th>Repo</th><th>Path</th><th>Type</th><th>Tool</th><th>Preview</th></tr></thead>
      <tbody>{(data.repos || []).map((r, i) =>
        <tr key={i}><td><code>{r.repo_url}</code></td><td>{r.file_path || ''}</td>
        <td>{r.secret_type || ''}</td><td>{r.tool}</td><td className="muted">{r.secret_preview || ''}</td></tr>)}
      </tbody></table>
    </div>
  );
}

function Cves({ data }) {
  const cves = [];
  (data.techs || []).forEach(t => {
    (t.cve_ids || []).slice(0, 3).forEach(cid =>
      cves.push({ cve: cid, cvss: t.cvss_max || 0, product: t.name + ' ' + t.version, asset: t.asset_name }));
  });
  cves.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  return (
    <div className="card"><h2>CVE exposure list (sorted by CVSS)</h2>
      <table><thead><tr><th>CVE</th><th>CVSS</th><th>Product</th><th>Asset</th></tr></thead>
      <tbody>{cves.map((c, i) =>
        <tr key={i}><td><code>{c.cve}</code></td><td><ScoreBadge score={c.cvss} /></td>
        <td>{c.product}</td><td>{c.asset}</td></tr>)}
      </tbody></table>
    </div>
  );
}

function Certs({ data }) {
  const months = data.certs_by_month || [];
  return (
    <div className="card"><h2>Certificate timeline (issued per month)</h2>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={months}><CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="month" /><YAxis allowDecimals={false} /><Tooltip />
          <Area type="monotone" dataKey="issued" stroke="#3a6ea5" fill="#3a6ea5" fillOpacity={0.35} /></AreaChart>
      </ResponsiveContainer>
      <table><thead><tr><th>Not before</th><th>Not after</th><th>Issuer</th><th>Names</th></tr></thead>
      <tbody>{(data.certs || []).slice(0, 50).map((c, i) =>
        <tr key={i}><td>{c.not_before}</td><td>{c.not_after}</td><td>{c.issuer || ''}</td>
        <td>{(c.domains || []).slice(0, 6).join(', ')}</td></tr>)}
      </tbody></table>
    </div>
  );
}

function Takeovers({ data }) {
  const rows = (data.takeovers || []).concat((data.shadows || []).map(s =>
    ({ hostname: s.hostname, cname_target: '', service: 'SHADOW IT', status: s.reason })));
  return (
    <div className="card"><h2>Subdomain takeover &amp; shadow IT candidates</h2>
      <table><thead><tr><th>Hostname</th><th>CNAME</th><th>Service</th><th>Status</th></tr></thead>
      <tbody>{rows.map((t, i) =>
        <tr key={i}><td><code>{t.hostname}</code></td><td>{t.cname_target || ''}</td>
        <td>{t.service}</td><td>{t.status}</td></tr>)}
      </tbody></table>
    </div>
  );
}

function People({ data }) {
  return (
    <div><div className="card"><h2>Employees</h2>
      <table><thead><tr><th>Name</th><th>Email</th><th>Title</th><th>Executive</th></tr></thead>
      <tbody>{(data.employees || []).map((e, i) =>
        <tr key={i}><td>{e.name}</td><td>{e.email || ''}</td><td>{e.title || ''}</td>
        <td>{e.is_executive ? 'yes' : ''}</td></tr>)}
      </tbody></table></div>
      <div className="card"><h2>Email candidates</h2>
      <table><thead><tr><th>Email</th><th>Status</th></tr></thead>
      <tbody>{(data.emails || []).map((e, i) =>
        <tr key={i}><td><code>{e.email}</code></td><td>{e.status}</td></tr>)}
      </tbody></table></div>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
