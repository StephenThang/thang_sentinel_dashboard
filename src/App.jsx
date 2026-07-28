import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";

/* ═══════════════════════════════════════════════════════════════
   THANG SENTINEL — Enterprise Security Monitoring Platform (SIEM)
   Live-simulated SOC: auth telemetry, netflow, detection engine,
   MITRE ATT&CK mapping, global threat tracing, IP forensics.
   ═══════════════════════════════════════════════════════════════ */

const HQ = { name: "Sentinel Corp HQ — Dallas, TX", lat: 32.78, lon: -96.8 };

const ACTORS = [
  { country: "Russia", flag: "🇷🇺", city: "Moscow", lat: 55.75, lon: 37.62, prefix: "185.220", asn: "AS204428 SELECTEL-MSK", aggression: 0.92, group: "COZY OTTER" },
  { country: "China", flag: "🇨🇳", city: "Beijing", lat: 39.9, lon: 116.4, prefix: "223.113", asn: "AS4134 CHINANET", aggression: 0.88, group: "JADE TYPHOON" },
  { country: "North Korea", flag: "🇰🇵", city: "Pyongyang", lat: 39.03, lon: 125.75, prefix: "175.45", asn: "AS131279 STAR-KP", aggression: 0.7, group: "LAZARUS-SIM" },
  { country: "Iran", flag: "🇮🇷", city: "Tehran", lat: 35.69, lon: 51.39, prefix: "91.99", asn: "AS58224 TCI", aggression: 0.66, group: "CRIMSON SANDSTORM" },
  { country: "Brazil", flag: "🇧🇷", city: "São Paulo", lat: -23.55, lon: -46.63, prefix: "177.54", asn: "AS28573 CLARO SA", aggression: 0.52, group: "BOTNET MIRAI-BR" },
  { country: "Vietnam", flag: "🇻🇳", city: "Hanoi", lat: 21.03, lon: 105.85, prefix: "113.160", asn: "AS45899 VNPT", aggression: 0.5, group: "BOTNET GAFGYT" },
  { country: "Netherlands", flag: "🇳🇱", city: "Amsterdam", lat: 52.37, lon: 4.9, prefix: "45.140", asn: "AS49870 ALSYCON BV", aggression: 0.58, group: "BULLETPROOF-NL" },
  { country: "Romania", flag: "🇷🇴", city: "Bucharest", lat: 44.43, lon: 26.1, prefix: "89.34", asn: "AS9009 M247", aggression: 0.48, group: "OUTLAW GANG" },
  { country: "India", flag: "🇮🇳", city: "Mumbai", lat: 19.08, lon: 72.88, prefix: "103.21", asn: "AS55836 RELIANCE JIO", aggression: 0.42, group: "BOTNET XORDDOS" },
  { country: "Nigeria", flag: "🇳🇬", city: "Lagos", lat: 6.52, lon: 3.38, prefix: "197.210", asn: "AS29465 MTN-NG", aggression: 0.38, group: "SILVER TERRIER" },
  { country: "United States", flag: "🇺🇸", city: "Ashburn, VA", lat: 39.04, lon: -77.49, prefix: "23.94", asn: "AS36352 COLOCROSSING", aggression: 0.45, group: "PROXY EXIT NODE" },
  { country: "Germany", flag: "🇩🇪", city: "Frankfurt", lat: 50.11, lon: 8.68, prefix: "195.90", asn: "AS24940 HETZNER", aggression: 0.4, group: "TOR EXIT RELAY" },
];

const TARGET_USERS = ["root", "admin", "administrator", "svc_backup", "oracle", "postgres", "jenkins", "guest", "test", "ubuntu", "ftpuser", "svc_web", "hr_admin", "sql_svc", "devops"];
const LEGIT_USERS = ["sec.analyst1", "netops.admin", "dev.deploy", "it.support", "hr.portal", "fin.user2", "qa.tester", "eng.build", "svc.backup2", "sales.crm"];
const LEGIT_SITES = [
  { city: "Dallas, TX", country: "United States", flag: "🇺🇸", lat: 32.78, lon: -96.8 },
  { city: "Chicago, IL", country: "United States", flag: "🇺🇸", lat: 41.88, lon: -87.63 },
  { city: "Denver, CO", country: "United States", flag: "🇺🇸", lat: 39.74, lon: -104.99 },
  { city: "Seattle, WA", country: "United States", flag: "🇺🇸", lat: 47.61, lon: -122.33 },
  { city: "Toronto, ON", country: "Canada", flag: "🇨🇦", lat: 43.65, lon: -79.38 },
  { city: "London", country: "United Kingdom", flag: "🇬🇧", lat: 51.51, lon: -0.13 },
];
const SERVICES = [
  { name: "SSH", port: 22 }, { name: "RDP", port: 3389 }, { name: "VPN", port: 443 },
  { name: "WEB", port: 443 }, { name: "SMTP", port: 25 }, { name: "FTP", port: 21 }, { name: "O365", port: 443 },
];
const SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443];

const rnd = (n) => Math.random() * n;
const pick = (a) => a[Math.floor(Math.random() * a.length)];
const ri = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
const pad = (n) => String(n).padStart(2, "0");
const fmtTime = (d) => `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
const fmtNum = (n) => (n >= 1e6 ? (n / 1e6).toFixed(1) + "M" : n >= 1e3 ? (n / 1e3).toFixed(1) + "K" : String(n));

function pickActor() {
  const total = ACTORS.reduce((s, a) => s + a.aggression, 0);
  let r = Math.random() * total;
  for (const a of ACTORS) { r -= a.aggression; if (r <= 0) return a; }
  return ACTORS[0];
}

/* Equirectangular projection into a 1000×500 viewBox */
const PX = (lon) => ((lon + 180) / 360) * 1000;
const PY = (lat) => ((90 - lat) / 180) * 500;
const toPath = (pts) => "M" + pts.map(([lon, lat]) => `${PX(lon).toFixed(1)},${PY(lat).toFixed(1)}`).join("L") + "Z";

/* Simplified continent outlines [lon, lat] */
const LAND = [
  // North America
  [[-166,68],[-155,71],[-140,70],[-128,70],[-115,73],[-100,73],[-88,69],[-82,62],[-75,59],[-68,58],[-64,47],[-70,43],[-74,40],[-76,35],[-80,32],[-81,26],[-83,29],[-89,29],[-95,27],[-97,22],[-94,18],[-87,15],[-83,9],[-79,8],[-85,13],[-95,16],[-105,20],[-110,24],[-117,33],[-124,40],[-124,48],[-135,58],[-152,59],[-165,60]],
  // Greenland
  [[-45,60],[-53,66],[-56,71],[-50,76],[-38,78],[-25,73],[-22,70],[-32,66]],
  // South America
  [[-79,8],[-72,12],[-64,10],[-56,6],[-50,0],[-44,-3],[-38,-6],[-35,-9],[-39,-14],[-41,-22],[-48,-27],[-53,-34],[-58,-38],[-62,-40],[-65,-45],[-68,-50],[-71,-54],[-73,-50],[-73,-44],[-72,-35],[-70,-25],[-70,-18],[-75,-14],[-79,-6],[-81,-2],[-79,2],[-77,7]],
  // Eurasia
  [[-10,36],[-9,43],[-5,48],[1,50],[4,53],[8,57],[5,61],[12,66],[18,70],[28,71],[40,68],[55,69],[70,73],[85,74],[100,77],[115,74],[130,72],[145,70],[160,70],[178,66],[178,63],[162,60],[155,52],[142,47],[135,43],[129,42],[122,39],[121,30],[115,22],[108,13],[105,9],[100,9],[97,13],[91,21],[87,22],[83,18],[80,13],[77,8],[73,16],[70,21],[66,25],[60,25],[54,26],[48,30],[43,35],[36,36],[27,36],[22,38],[18,40],[13,38],[6,37],[-6,36]],
  // UK
  [[-5,50],[-5,54],[-6,58],[-2,58],[0,53],[1,51],[-3,50]],
  // Japan
  [[130,31],[132,34],[136,35],[140,36],[141,41],[143,44],[140,42],[137,37],[133,34],[130,33]],
  // Africa
  [[-17,15],[-16,22],[-10,30],[-6,35],[3,37],[11,37],[11,33],[20,32],[25,31],[32,31],[34,27],[43,11],[51,12],[48,4],[42,-2],[40,-10],[35,-20],[33,-26],[28,-33],[20,-35],[17,-32],[14,-24],[12,-18],[13,-11],[9,-2],[9,4],[4,6],[-4,5],[-8,5],[-13,9]],
  // Australia
  [[114,-22],[114,-34],[119,-35],[126,-33],[132,-32],[136,-35],[140,-38],[147,-39],[150,-37],[153,-30],[153,-25],[147,-19],[142,-11],[136,-12],[131,-12],[126,-14],[121,-19]],
  // Indonesia strip
  [[95,5],[100,2],[104,0],[102,-3],[106,-6],[112,-7],[115,-8],[114,-6],[108,-5],[104,-1],[98,3]],
].map(toPath);

const SEV = {
  critical: { label: "CRITICAL", color: "#FF5C7A" },
  high: { label: "HIGH", color: "#FF9F45" },
  medium: { label: "MEDIUM", color: "#FFD166" },
  low: { label: "LOW", color: "#4FD8EB" },
};

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap');
:root{
  --bg:#080D1C; --panel:#0E1630; --panel2:#111B3A; --line:#1C2A52; --line2:#28396B;
  --txt:#D9E4F8; --mut:#6E7FA6; --dim:#42517A;
  --cyan:#4FD8EB; --violet:#8B7BFF; --amber:#FFB454; --red:#FF5C7A; --green:#3DDC97; --gold:#FFD166;
  --mono:'IBM Plex Mono',ui-monospace,'SF Mono',Consolas,monospace;
  --disp:'Chakra Petch','Inter',sans-serif;
  --body:'Inter',system-ui,sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
.ts-root{min-height:100vh;background:radial-gradient(1200px 700px at 70% -10%,#0F1B42 0%,var(--bg) 55%),var(--bg);color:var(--txt);font-family:var(--body);font-size:13px;padding:14px 16px 26px}
.ts-grid{display:grid;grid-template-columns:repeat(12,1fr);gap:12px;max-width:1560px;margin:0 auto}
.panel{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:10px;position:relative;overflow:hidden}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,rgba(79,216,235,.35),transparent)}
.ph{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid var(--line)}
.ph h3{font-family:var(--disp);font-size:11px;font-weight:600;letter-spacing:.18em;color:var(--mut);text-transform:uppercase;display:flex;gap:8px;align-items:center}
.ph h3 .tick{color:var(--cyan)}
.kpi{padding:12px 14px;display:flex;flex-direction:column;gap:6px}
.kpi .lb{font-family:var(--disp);font-size:9.5px;letter-spacing:.16em;color:var(--mut);text-transform:uppercase}
.kpi .v{font-family:var(--mono);font-size:24px;font-weight:600;line-height:1}
.kpi .sub{font-family:var(--mono);font-size:10px;color:var(--dim)}
.mono{font-family:var(--mono)}
.chip{font-family:var(--mono);font-size:9.5px;font-weight:600;letter-spacing:.06em;padding:2px 7px;border-radius:4px;border:1px solid}
.btn{font-family:var(--disp);font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;background:#152147;border:1px solid var(--line2);color:var(--txt);border-radius:6px;padding:6px 11px;cursor:pointer;transition:all .15s}
.btn:hover{border-color:var(--cyan);color:var(--cyan);box-shadow:0 0 12px rgba(79,216,235,.25)}
.btn.danger:hover{border-color:var(--red);color:var(--red);box-shadow:0 0 12px rgba(255,92,122,.25)}
.btn:focus-visible,.iplink:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.iplink{background:none;border:none;color:var(--cyan);font-family:var(--mono);font-size:inherit;cursor:pointer;padding:0;text-decoration:underline dotted rgba(79,216,235,.5);text-underline-offset:3px}
.iplink:hover{text-shadow:0 0 8px rgba(79,216,235,.6)}
.feed{overflow-y:auto;font-family:var(--mono);font-size:11px}
.feed::-webkit-scrollbar,.alerts::-webkit-scrollbar{width:8px}
.feed::-webkit-scrollbar-thumb,.alerts::-webkit-scrollbar-thumb{background:var(--line2);border-radius:4px}
.evrow{display:grid;grid-template-columns:62px 46px 128px 1fr 86px;gap:10px;padding:5px 14px;border-bottom:1px solid rgba(28,42,82,.5);align-items:center;animation:slidein .3s ease}
.evrow:hover{background:rgba(79,216,235,.04)}
@keyframes slidein{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@keyframes pulse{0%{transform:scale(.6);opacity:.9}70%{transform:scale(2.6);opacity:0}100%{opacity:0}}
@keyframes dashmove{to{stroke-dashoffset:-26}}
@keyframes sweep{to{transform:rotate(360deg)}}
@keyframes blink{50%{opacity:.25}}
.live-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 1.6s infinite}
.paused .live-dot{background:var(--amber);box-shadow:0 0 8px var(--amber);animation:none}
.alerts{overflow-y:auto;display:flex;flex-direction:column;gap:8px;padding:10px 12px}
.alert-card{border:1px solid var(--line);border-left:3px solid;border-radius:8px;padding:9px 11px;background:rgba(8,13,28,.55);animation:slidein .35s ease}
.searchbox{flex:1;max-width:520px;display:flex;align-items:center;gap:8px;background:#0A1128;border:1px solid var(--line2);border-radius:8px;padding:7px 12px}
.searchbox input{flex:1;background:none;border:none;outline:none;color:var(--cyan);font-family:var(--mono);font-size:12px}
.searchbox input::placeholder{color:var(--dim)}
table.tbl{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
.tbl th{font-family:var(--disp);font-size:9px;letter-spacing:.15em;text-transform:uppercase;color:var(--mut);text-align:left;padding:7px 14px;border-bottom:1px solid var(--line)}
.tbl td{padding:6px 14px;border-bottom:1px solid rgba(28,42,82,.45)}
.tbl tr:hover td{background:rgba(79,216,235,.04)}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(430px,94vw);background:linear-gradient(180deg,#101A3C,#0B1226);border-left:1px solid var(--line2);z-index:60;padding:18px;overflow-y:auto;box-shadow:-20px 0 60px rgba(0,0,0,.6);animation:drawerin .25s ease}
@keyframes drawerin{from{transform:translateX(40px);opacity:0}to{transform:none;opacity:1}}
.overlay{position:fixed;inset:0;background:rgba(4,7,16,.55);backdrop-filter:blur(2px);z-index:50}
.kv{display:grid;grid-template-columns:120px 1fr;gap:5px 12px;font-family:var(--mono);font-size:11.5px}
.kv .k{color:var(--mut)}
.hop{display:flex;align-items:center;gap:10px;padding:7px 0;font-family:var(--mono);font-size:11px;opacity:0;animation:slidein .4s ease forwards}
.scanlines::after{content:'';position:absolute;inset:0;pointer-events:none;background:repeating-linear-gradient(0deg,rgba(255,255,255,.015) 0 1px,transparent 1px 3px)}
.col8{grid-column:span 8}.col7{grid-column:span 7}.col5{grid-column:span 5}.col4{grid-column:span 4}.col2{grid-column:span 2}.col12{grid-column:span 12}
@media(max-width:1100px){.col8,.col7,.col5,.col4{grid-column:span 12}.col2{grid-column:span 4}}
@media(max-width:620px){.col2{grid-column:span 6}.evrow{grid-template-columns:56px 40px 1fr;overflow:hidden}}
.kpi-card{transition:box-shadow .2s,border-color .2s,transform .2s}
.kpi-card:hover{border-color:var(--line2);box-shadow:0 0 20px rgba(79,216,235,.1);transform:translateY(-1px)}
.qchip{font-family:var(--mono);font-size:9.5px;color:var(--mut);border:1px solid var(--line);border-radius:20px;padding:2px 9px;cursor:pointer;background:none;transition:all .15s}
.qchip:hover{color:var(--cyan);border-color:var(--cyan)}
.fchip{font-family:var(--disp);font-size:9px;font-weight:600;letter-spacing:.08em;padding:3px 10px;border-radius:14px;border:1px solid var(--line);background:none;color:var(--mut);cursor:pointer;text-transform:uppercase;transition:all .15s}
.fchip.on{color:var(--cyan);border-color:var(--cyan);background:rgba(79,216,235,.08);box-shadow:0 0 10px rgba(79,216,235,.15)}
.fchip:hover{color:var(--txt)}
.toasts{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);display:flex;flex-direction:column;gap:8px;z-index:80;align-items:center}
.toast{font-family:var(--mono);font-size:11px;background:#0F1B3E;border:1px solid var(--cyan);color:var(--cyan);border-radius:8px;padding:8px 14px;box-shadow:0 0 20px rgba(79,216,235,.25);animation:slidein .25s ease}
.toast.red{border-color:var(--red);color:var(--red);box-shadow:0 0 20px rgba(255,92,122,.25)}
.critband{display:flex;align-items:center;gap:6px;font-family:var(--disp);font-size:10px;font-weight:600;letter-spacing:.14em;color:var(--red);border:1px solid var(--red);border-radius:6px;padding:5px 10px;background:rgba(255,92,122,.08);animation:blink 1.2s infinite}
.boot{position:fixed;inset:0;background:#060A16;z-index:100;display:grid;place-items:center;animation:bootout .45s ease 2s forwards;pointer-events:none}
@keyframes bootout{to{opacity:0;visibility:hidden}}
.bootlines{font-family:var(--mono);font-size:12px;width:min(440px,90vw)}
.bootlines div{opacity:0;animation:slidein .3s ease forwards;margin-bottom:7px}
.feedhead{display:grid;grid-template-columns:62px 46px 128px 1fr 86px;gap:10px;padding:6px 14px;font-family:var(--disp);font-size:8.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--dim);border-bottom:1px solid var(--line)}
.alert-card{box-shadow:inset 4px 0 14px -8px currentColor}
@media(max-width:620px){.feedhead{display:none}}
@media(prefers-reduced-motion:reduce){*{animation-duration:.001s !important;animation-iteration-count:1 !important}.boot{display:none}}
`;

/* ═══════════════ SIMULATION + DETECTION ENGINE ═══════════════ */

function useSimulation() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [traffic, setTraffic] = useState([]);
  const [attackers, setAttackers] = useState({});
  const [blocked, setBlocked] = useState([]);
  const [totals, setTotals] = useState({ events: 14382, failed: 3120, success: 9871, dropped: 402, dataGB: 41.7 });
  const [paused, setPaused] = useState(false);
  const [speed, setSpeed] = useState(1);
  const sim = useRef({ id: 1000, ipStats: {}, campaigns: [], blockedSet: new Set(), ipPool: {}, epsWindow: [] });

  const mkIP = (actor) => {
    const pool = (sim.current.ipPool[actor.country] ||= []);
    if (pool.length < 4 || Math.random() < 0.25) {
      const ip = `${actor.prefix}.${ri(1, 254)}.${ri(1, 254)}`;
      pool.push(ip); if (pool.length > 7) pool.shift();
      return ip;
    }
    return pick(pool);
  };

  const pushAlert = useCallback((a) => {
    setAlerts((prev) => [{ id: "AL-" + sim.current.id++, ts: new Date(), status: "open", ...a }, ...prev].slice(0, 40));
  }, []);

  const registerAttack = (ip, actor) => {
    setAttackers((prev) => {
      const cur = prev[ip] || { ip, actor, count: 0, first: new Date() };
      return { ...prev, [ip]: { ...cur, count: cur.count + 1, last: new Date() } };
    });
  };

  const ipStat = (ip, actor) => (sim.current.ipStats[ip] ||= { fails: 0, users: new Set(), ports: new Set(), actor, alerted: {} });

  const genEvents = useCallback(() => {
    const S = sim.current;
    const out = [];
    const now = new Date();
    const mk = (e) => out.push({ id: S.id++, ts: now, ...e });

    // spawn attack campaigns
    if (S.campaigns.length < 2 && Math.random() < 0.07) {
      const actor = pickActor();
      S.campaigns.push({ actor, ip: mkIP(actor), kind: pick(["bruteforce", "spray", "portscan"]), left: ri(16, 34), user: pick(TARGET_USERS), svc: pick(SERVICES) });
    }

    // benign enterprise noise
    const nBenign = ri(1, 3);
    for (let i = 0; i < nBenign; i++) {
      const site = pick(LEGIT_SITES);
      const user = pick(LEGIT_USERS);
      if (Math.random() < 0.62) {
        const fail = Math.random() < 0.06;
        mk({ type: "auth", outcome: fail ? "failed" : "success", user, svc: pick(["VPN", "O365", "SSH", "WEB"]), ip: `10.${ri(1, 30)}.${ri(0, 255)}.${ri(2, 254)}`, geo: site, benign: true, msg: fail ? "Invalid password (typo)" : "Authentication OK · MFA verified" });
      } else {
        mk({ type: "net", outcome: "allow", user: "-", svc: "HTTPS", port: 443, ip: `10.${ri(1, 30)}.${ri(0, 255)}.${ri(2, 254)}`, geo: site, benign: true, bytes: ri(4, 900) * 1024, msg: "Outbound TLS session established" });
      }
    }

    // opportunistic attacker probes
    const nProbe = Math.random() < 0.75 ? ri(1, 2) : 0;
    for (let i = 0; i < nProbe; i++) {
      const actor = pickActor();
      const ip = mkIP(actor);
      if (S.blockedSet.has(ip)) { mk({ type: "fw", outcome: "dropped", user: "-", svc: "FW", ip, geo: actor, msg: "Packet dropped · IP on blocklist", attack: true }); continue; }
      const svc = pick(SERVICES);
      const user = pick(TARGET_USERS);
      const st = ipStat(ip, actor);
      st.fails++; st.users.add(user);
      registerAttack(ip, actor);
      mk({ type: "auth", outcome: "failed", user, svc: svc.name, ip, geo: actor, attack: true, msg: `Failed password for ${user} · port ${svc.port}` });
    }

    // active campaigns burn hotter
    S.campaigns = S.campaigns.filter((c) => {
      if (S.blockedSet.has(c.ip)) return false;
      const st = ipStat(c.ip, c.actor);
      const n = ri(1, 2);
      for (let i = 0; i < n; i++) {
        registerAttack(c.ip, c.actor);
        if (c.kind === "portscan") {
          const port = pick(SCAN_PORTS);
          st.ports.add(port);
          mk({ type: "net", outcome: "deny", user: "-", svc: "SCAN", port, ip: c.ip, geo: c.actor, attack: true, msg: `SYN probe → tcp/${port} · no service banner returned` });
        } else {
          const user = c.kind === "spray" ? pick(TARGET_USERS) : c.user;
          st.fails++; st.users.add(user);
          // rare breach → critical
          if (c.kind === "bruteforce" && st.fails > 14 && Math.random() < 0.045 && !st.alerted.breach) {
            st.alerted.breach = true;
            mk({ type: "auth", outcome: "success", user, svc: c.svc.name, ip: c.ip, geo: c.actor, attack: true, msg: `SUCCESSFUL login for ${user} after ${st.fails} failures` });
            pushAlert({ sev: "critical", title: "Credential compromise — brute force succeeded", desc: `Account "${user}" authenticated from ${c.actor.city}, ${c.actor.country} after ${st.fails} consecutive failures on ${c.svc.name}. Session requires immediate containment.`, ip: c.ip, actor: c.actor, mitre: "T1110 → T1078", rule: "SENT-004 Post-Bruteforce Success" });
          } else {
            mk({ type: "auth", outcome: "failed", user, svc: c.svc.name, ip: c.ip, geo: c.actor, attack: true, msg: `Failed password for ${user} · attempt #${st.fails}` });
          }
        }
      }
      c.left -= n;
      return c.left > 0;
    });

    // occasional IDS signature hits
    if (Math.random() < 0.08) {
      const actor = pickActor();
      const ip = mkIP(actor);
      if (!S.blockedSet.has(ip)) {
        registerAttack(ip, actor);
        const sig = pick([
          { t: "SQL injection attempt on /login.php", m: "T1190", sev: "high" },
          { t: "Log4Shell JNDI string in User-Agent", m: "T1190", sev: "critical" },
          { t: "Nmap OS fingerprint signature", m: "T1046", sev: "medium" },
          { t: "Known C2 beacon pattern (Cobalt Strike)", m: "T1071.001", sev: "critical" },
          { t: "Directory traversal ../ sequence", m: "T1083", sev: "medium" },
        ]);
        mk({ type: "ids", outcome: "alert", user: "-", svc: "IDS", ip, geo: actor, attack: true, msg: sig.t });
        pushAlert({ sev: sig.sev, title: `IDS: ${sig.t}`, desc: `Suricata signature matched on perimeter sensor. Source traced to ${actor.asn} (${actor.city}, ${actor.country}) · attributed activity cluster: ${actor.group}.`, ip, actor, mitre: sig.m, rule: "SENT-010 IDS Signature Match" });
      }
    }

    // ── DETECTION RULES over per-IP state ──
    for (const [ip, st] of Object.entries(S.ipStats)) {
      if (S.blockedSet.has(ip)) continue;
      if (st.fails >= 8 && st.users.size <= 2 && !st.alerted.bf) {
        st.alerted.bf = true;
        pushAlert({ sev: "high", title: "Brute-force attack in progress", desc: `${st.fails} failed logins against account "${[...st.users][0]}" from a single source in the current window. Origin: ${st.actor.city}, ${st.actor.country} (${st.actor.asn}).`, ip, actor: st.actor, mitre: "T1110.001", rule: "SENT-001 Auth Failure Threshold" });
      }
      if (st.users.size >= 6 && !st.alerted.spray) {
        st.alerted.spray = true;
        pushAlert({ sev: "high", title: "Password spraying detected", desc: `Single source attempted ${st.users.size} distinct accounts (${[...st.users].slice(0, 4).join(", ")}…) — low-and-slow spray pattern consistent with ${st.actor.group}.`, ip, actor: st.actor, mitre: "T1110.003", rule: "SENT-002 Distinct-User Spread" });
      }
      if (st.ports.size >= 9 && !st.alerted.scan) {
        st.alerted.scan = true;
        pushAlert({ sev: "medium", title: "Port scan / network reconnaissance", desc: `${st.ports.size} unique TCP ports probed from one host in under a minute. Likely service enumeration ahead of exploitation.`, ip, actor: st.actor, mitre: "T1046", rule: "SENT-003 Port Fan-Out" });
      }
    }
    return out;
  }, [pushAlert]);

  useEffect(() => {
    if (paused) return;
    const iv = setInterval(() => {
      const batch = genEvents();
      const S = sim.current;
      S.epsWindow.push({ t: Date.now(), n: batch.length });
      S.epsWindow = S.epsWindow.filter((w) => Date.now() - w.t < 5000);
      setEvents((prev) => [...batch.reverse(), ...prev].slice(0, 130));
      setTotals((p) => ({
        events: p.events + batch.length,
        failed: p.failed + batch.filter((e) => e.outcome === "failed").length,
        success: p.success + batch.filter((e) => e.outcome === "success").length,
        dropped: p.dropped + batch.filter((e) => e.outcome === "dropped").length,
        dataGB: p.dataGB + batch.length * 0.0004,
      }));
      const load = S.campaigns.length;
      setTraffic((prev) => [...prev, {
        t: Date.now(),
        inb: 120 + rnd(60) + load * (40 + rnd(60)) + (Math.random() < 0.05 ? rnd(180) : 0),
        out: 80 + rnd(40) + load * 12,
        fails: batch.filter((e) => e.outcome === "failed" && e.attack).length,
      }].slice(-64));
    }, 850 / speed);
    return () => clearInterval(iv);
  }, [paused, speed, genEvents]);

  const blockIP = useCallback((ip) => {
    sim.current.blockedSet.add(ip);
    setBlocked((p) => (p.includes(ip) ? p : [ip, ...p]));
    setAlerts((prev) => prev.map((a) => (a.ip === ip && a.status !== "blocked" ? { ...a, status: "blocked" } : a)));
    pushAlert({ sev: "low", title: `Containment: ${ip} blocked at perimeter`, desc: "Deny rule pushed to edge firewall and WAF. All further packets from this source will be dropped and logged.", ip, actor: sim.current.ipStats[ip]?.actor, mitre: "RESPONSE", rule: "SOAR Playbook PB-07" });
  }, [pushAlert]);

  const ackAlert = useCallback((id) => setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status: "ack" } : a))), []);

  const eps = sim.current.epsWindow.reduce((s, w) => s + w.n, 0) / 5;
  return { events, alerts, traffic, attackers, blocked, totals, paused, setPaused, speed, setSpeed, blockIP, ackAlert, eps, campaigns: sim.current.campaigns.length };
}

/* SPL-style search: free text + key=value (status/src/user/country/type/service), * wildcard */
function matchQuery(e, q) {
  if (!q.trim()) return true;
  const tokens = q.trim().split(/\s+/);
  return tokens.every((tok) => {
    const m = tok.match(/^(\w+)=(.+)$/);
    if (m) {
      const [, k, vRaw] = m;
      const v = vRaw.toLowerCase();
      const field = { status: e.outcome, outcome: e.outcome, src: e.ip, ip: e.ip, user: e.user, country: e.geo?.country, type: e.type, service: e.svc, svc: e.svc }[k.toLowerCase()];
      if (field == null) return false;
      const f = String(field).toLowerCase();
      if (v.includes("*")) return new RegExp("^" + v.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$").test(f);
      return f === v;
    }
    const hay = `${e.msg} ${e.ip} ${e.user} ${e.svc} ${e.geo?.country} ${e.geo?.city} ${e.outcome}`.toLowerCase();
    return hay.includes(tok.toLowerCase());
  });
}

/* ═══════════════════ VISUAL COMPONENTS ═══════════════════ */

const Spark = ({ data, color, h = 26, w = 100 }) => {
  if (!data.length) return <svg width={w} height={h} />;
  const max = Math.max(...data, 1);
  const pts = data.map((v, i) => `${(i / (data.length - 1 || 1)) * w},${h - (v / max) * (h - 3) - 1}`).join(" ");
  return (
    <svg width={w} height={h} style={{ overflow: "visible" }} aria-hidden>
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.6" strokeLinejoin="round" opacity=".9" />
      <polygon points={`0,${h} ${pts} ${w},${h}`} fill={color} opacity=".12" />
    </svg>
  );
};

const TrafficChart = ({ traffic }) => {
  const W = 560, H = 150, P = 6;
  const max = Math.max(...traffic.map((t) => t.inb), 200);
  const X = (i) => P + (i / Math.max(traffic.length - 1, 1)) * (W - P * 2);
  const Y = (v) => H - 24 - (v / max) * (H - 40);
  const area = (key) => {
    if (traffic.length < 2) return "";
    const line = traffic.map((t, i) => `${X(i).toFixed(1)},${Y(t[key]).toFixed(1)}`).join("L");
    return `M${X(0)},${H - 24}L${line}L${X(traffic.length - 1)},${H - 24}Z`;
  };
  const path = (key) => (traffic.length < 2 ? "" : "M" + traffic.map((t, i) => `${X(i).toFixed(1)},${Y(t[key]).toFixed(1)}`).join("L"));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", display: "block" }}>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1={P} x2={W - P} y1={H - 24 - f * (H - 40)} y2={H - 24 - f * (H - 40)} stroke="#1C2A52" strokeDasharray="3 5" strokeWidth="1" />
      ))}
      <path d={area("inb")} fill="#4FD8EB" opacity=".13" />
      <path d={path("inb")} fill="none" stroke="#4FD8EB" strokeWidth="1.8" />
      <path d={area("out")} fill="#8B7BFF" opacity=".12" />
      <path d={path("out")} fill="none" stroke="#8B7BFF" strokeWidth="1.6" />
      {traffic.map((t, i) => t.fails > 0 && (
        <rect key={t.t} x={X(i) - 1.5} y={H - 22} width="3" height={Math.min(t.fails * 4, 16)} fill="#FF5C7A" opacity=".85" rx="1" />
      ))}
      <text x={P} y={H - 6} fill="#6E7FA6" fontSize="9" fontFamily="var(--mono)">▬ inbound Mbps</text>
      <text x={P + 105} y={H - 6} fill="#8B7BFF" fontSize="9" fontFamily="var(--mono)">▬ outbound</text>
      <text x={P + 190} y={H - 6} fill="#FF5C7A" fontSize="9" fontFamily="var(--mono)">▮ failed auths</text>
      <text x={W - P} y={12} fill="#42517A" fontSize="9" fontFamily="var(--mono)" textAnchor="end">peak {Math.round(max)} Mbps</text>
    </svg>
  );
};

const ThreatMap = ({ events, onPick, paused }) => {
  const arcs = useMemo(() => {
    const seen = new Set(); const out = [];
    for (const e of events) {
      if (!e.attack || !e.geo?.lat || seen.has(e.ip)) continue;
      seen.add(e.ip); out.push(e);
      if (out.length >= 9) break;
    }
    return out;
  }, [events]);
  const hx = PX(HQ.lon), hy = PY(HQ.lat);
  return (
    <svg viewBox="0 0 1000 500" style={{ width: "100%", display: "block", background: "radial-gradient(700px 350px at 50% 40%, rgba(23,38,84,.55), transparent 70%)" }} role="img" aria-label="Global threat map showing live attack origins">
      <defs>
        <radialGradient id="sweepg" cx="0" cy="0" r="1">
          <stop offset="0%" stopColor="#4FD8EB" stopOpacity=".22" />
          <stop offset="100%" stopColor="#4FD8EB" stopOpacity="0" />
        </radialGradient>
      </defs>
      {/* graticule */}
      {[...Array(11)].map((_, i) => <line key={"v" + i} x1={i * 100} x2={i * 100} y1="0" y2="500" stroke="#131E42" strokeWidth="1" />)}
      {[...Array(5)].map((_, i) => <line key={"h" + i} x1="0" x2="1000" y1={i * 100 + 50} y2={i * 100 + 50} stroke="#131E42" strokeWidth="1" />)}
      {/* land */}
      {LAND.map((d, i) => <path key={i} d={d} fill="#16234C" stroke="#2A3C74" strokeWidth="1.1" strokeLinejoin="round" opacity=".95" />)}
      {/* radar sweep from HQ */}
      {!paused && (
        <g style={{ transformOrigin: `${hx}px ${hy}px`, animation: "sweep 7s linear infinite" }}>
          <path d={`M${hx},${hy} L${hx + 320},${hy - 115} A340,340 0 0 1 ${hx + 340},${hy} Z`} fill="url(#sweepg)" />
          <line x1={hx} y1={hy} x2={hx + 340} y2={hy} stroke="#4FD8EB" strokeWidth="1" opacity=".5" />
        </g>
      )}
      {/* HQ monitoring range rings */}
      {[70, 140, 210].map((r) => (
        <circle key={r} cx={hx} cy={hy} r={r} fill="none" stroke="#1E2F5E" strokeWidth="1" strokeDasharray="2 7" />
      ))}
      {/* legend */}
      <g fontFamily="var(--mono)" fontSize="9">
        <rect x="12" y="428" width="168" height="60" rx="6" fill="rgba(8,13,28,.75)" stroke="#1C2A52" />
        {[["#4FD8EB", "probe / brute force"], ["#FF9F45", "campaign traffic"], ["#FF5C7A", "breach — success"], ["#42517A", "dropped (blocked)"]].map(([c, t], i) => (
          <g key={t}>
            <circle cx="24" cy={440 + i * 12} r="2.8" fill={c} />
            <text x="33" y={443 + i * 12} fill="#6E7FA6">{t}</text>
          </g>
        ))}
      </g>
      {/* attack arcs */}
      {arcs.map((e, i) => {
        const x = PX(e.geo.lon), y = PY(e.geo.lat);
        const mx = (x + hx) / 2, my = Math.min(y, hy) - Math.hypot(x - hx, y - hy) * 0.22;
        const col = e.outcome === "success" ? "#FF5C7A" : e.outcome === "dropped" ? "#42517A" : i % 2 ? "#FF9F45" : "#4FD8EB";
        return (
          <g key={e.id} style={{ cursor: "pointer" }} onClick={() => onPick(e.ip)}>
            <path d={`M${x},${y} Q${mx},${my} ${hx},${hy}`} fill="none" stroke={col} strokeWidth="1.4" strokeDasharray="5 8" opacity=".8" style={{ animation: paused ? "none" : "dashmove 1.1s linear infinite" }} />
            <circle cx={x} cy={y} r="3.4" fill={col} />
            <circle cx={x} cy={y} r="3.4" fill="none" stroke={col} strokeWidth="1.5" style={{ transformOrigin: `${x}px ${y}px`, animation: paused ? "none" : "pulse 1.8s ease-out infinite" }} />
            <text x={x + 8} y={y + 3} fill={col} fontSize="10" fontFamily="var(--mono)" opacity=".95">{e.geo.flag} {e.ip}</text>
          </g>
        );
      })}
      {/* HQ */}
      <g>
        <circle cx={hx} cy={hy} r="4.5" fill="#3DDC97" />
        <circle cx={hx} cy={hy} r="4.5" fill="none" stroke="#3DDC97" strokeWidth="1.6" style={{ transformOrigin: `${hx}px ${hy}px`, animation: paused ? "none" : "pulse 2.4s ease-out infinite" }} />
        <text x={hx + 9} y={hy - 6} fill="#3DDC97" fontSize="10.5" fontFamily="var(--disp)" fontWeight="600" letterSpacing="1">⌂ {HQ.name}</text>
      </g>
    </svg>
  );
};

const ThreatGauge = ({ score }) => {
  const level = score >= 75 ? ["SEVERE", "#FF5C7A"] : score >= 50 ? ["HIGH", "#FF9F45"] : score >= 25 ? ["ELEVATED", "#FFD166"] : ["GUARDED", "#3DDC97"];
  const R = 62, C = Math.PI * R;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 18, padding: "14px 16px" }}>
      <svg width="150" height="86" viewBox="0 0 150 86">
        <path d={`M13,80 A${R},${R} 0 0 1 137,80`} fill="none" stroke="#1C2A52" strokeWidth="10" strokeLinecap="round" />
        <path d={`M13,80 A${R},${R} 0 0 1 137,80`} fill="none" stroke={level[1]} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={`${(score / 100) * C} ${C}`} style={{ transition: "stroke-dasharray .8s ease, stroke .8s", filter: `drop-shadow(0 0 6px ${level[1]}66)` }} />
        <text x="75" y="66" textAnchor="middle" fill={level[1]} fontSize="26" fontFamily="var(--mono)" fontWeight="600">{Math.round(score)}</text>
        <text x="75" y="80" textAnchor="middle" fill="#6E7FA6" fontSize="8" fontFamily="var(--disp)" letterSpacing="2">THREAT INDEX</text>
      </svg>
      <div>
        <div style={{ fontFamily: "var(--disp)", fontSize: 20, fontWeight: 700, letterSpacing: ".12em", color: level[1], textShadow: `0 0 14px ${level[1]}55` }}>{level[0]}</div>
        <div style={{ color: "var(--mut)", fontSize: 11, marginTop: 4, lineHeight: 1.5 }}>Composite of open alert severity, auth failure velocity, and active campaign count.</div>
      </div>
    </div>
  );
};

const Inspector = ({ ip, events, attackers, blocked, onBlock, onClose }) => {
  const info = attackers[ip];
  const evs = events.filter((e) => e.ip === ip);
  const actor = info?.actor || evs[0]?.geo;
  const isBlocked = blocked.includes(ip);
  const hops = actor ? [
    { n: "edge-fw-01.corp.internal", ip: "203.0.113.1", ms: 1 },
    { n: "core-rtr-01.transit.example.net", ip: "192.0.2.14", ms: 4 },
    { n: "ix-gw-02.peering.example.net", ip: "198.51.100.9", ms: 9 },
    { n: `bb-gw.${(actor.city || "unknown").split(",")[0].toLowerCase().replace(/\s/g, "")}.net`, ip: `${ip.split(".").slice(0, 2).join(".")}.0.1`, ms: ri(80, 190) },
    { n: `${(actor.asn || "AS0 UNKNOWN").split(" ")[0].toLowerCase()}.${actor.country?.slice(0, 2).toLowerCase()}`, ip, ms: ri(140, 260) },
  ] : [];
  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="drawer scanlines">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
          <div style={{ fontFamily: "var(--disp)", fontSize: 11, letterSpacing: ".2em", color: "var(--mut)" }}>IP FORENSICS</div>
          <button className="btn" onClick={onClose}>✕ Close</button>
        </div>
        <div className="mono" style={{ fontSize: 22, fontWeight: 600, color: "var(--cyan)", textShadow: "0 0 16px rgba(79,216,235,.4)" }}>{ip}</div>
        <div style={{ margin: "6px 0 16px", fontSize: 12, color: "var(--mut)" }}>{actor?.flag} {actor?.city}{actor?.country ? `, ${actor.country}` : ""}</div>
        <div className="kv" style={{ marginBottom: 18 }}>
          <span className="k">ASN / Org</span><span>{actor?.asn || "AS-PRIVATE Internal"}</span>
          <span className="k">Attribution</span><span style={{ color: "var(--violet)" }}>{actor?.group || "Unclassified"}</span>
          <span className="k">Events (session)</span><span>{info?.count ?? evs.length}</span>
          <span className="k">First seen</span><span>{info?.first ? fmtTime(info.first) : "—"}</span>
          <span className="k">Last seen</span><span>{info?.last ? fmtTime(info.last) : "—"}</span>
          <span className="k">Reputation</span><span style={{ color: actor?.aggression > 0.6 ? "var(--red)" : "var(--amber)" }}>{actor?.aggression ? Math.round(actor.aggression * 100) + "/100 malicious confidence" : "clean"}</span>
          <span className="k">Status</span><span style={{ color: isBlocked ? "var(--red)" : "var(--green)" }}>{isBlocked ? "⛔ BLOCKED at perimeter" : "◉ Traffic permitted"}</span>
        </div>
        {actor?.lat != null && (
          <>
            <div style={{ fontFamily: "var(--disp)", fontSize: 10, letterSpacing: ".18em", color: "var(--mut)", marginBottom: 6 }}>REVERSE TRACE ROUTE</div>
            <div style={{ borderLeft: "1px dashed var(--line2)", paddingLeft: 12, marginBottom: 18 }}>
              {hops.map((h, i) => (
                <div className="hop" key={h.n} style={{ animationDelay: `${i * 0.35}s` }}>
                  <span style={{ color: "var(--dim)" }}>{i + 1}</span>
                  <span style={{ color: i === hops.length - 1 ? "var(--red)" : "var(--txt)" }}>{h.n}</span>
                  <span style={{ color: "var(--dim)", marginLeft: "auto" }}>{h.ip}</span>
                  <span style={{ color: "var(--cyan)" }}>{h.ms}ms</span>
                </div>
              ))}
            </div>
          </>
        )}
        <div style={{ fontFamily: "var(--disp)", fontSize: 10, letterSpacing: ".18em", color: "var(--mut)", marginBottom: 6 }}>RECENT ACTIVITY</div>
        <div className="mono" style={{ fontSize: 10.5, display: "flex", flexDirection: "column", gap: 4, marginBottom: 20, maxHeight: 150, overflowY: "auto" }}>
          {evs.slice(0, 10).map((e) => (
            <div key={e.id} style={{ color: e.outcome === "success" && e.attack ? "var(--red)" : "var(--mut)" }}>
              {fmtTime(e.ts)} · {e.svc} · {e.msg}
            </div>
          ))}
          {!evs.length && <div style={{ color: "var(--dim)" }}>No events in current buffer.</div>}
        </div>
        {!isBlocked ? (
          <button className="btn danger" style={{ width: "100%", padding: 10, borderColor: "var(--red)", color: "var(--red)" }} onClick={() => onBlock(ip)}>⛔ Block IP at edge firewall</button>
        ) : (
          <div style={{ textAlign: "center", padding: 10, border: "1px solid var(--red)", borderRadius: 6, color: "var(--red)", fontFamily: "var(--disp)", fontSize: 11, letterSpacing: ".15em" }}>CONTAINED — DENY RULE ACTIVE</div>
        )}
      </div>
    </>
  );
};

/* ═══════════════════ MAIN APPLICATION ═══════════════════ */

export default function ThangSentinel() {
  const sim = useSimulation();
  const { events, alerts, traffic, attackers, blocked, totals, paused, setPaused, speed, setSpeed, blockIP, ackAlert, eps, campaigns } = sim;
  const [query, setQuery] = useState("");
  const [inspect, setInspect] = useState(null);
  const [clock, setClock] = useState(new Date());
  const [toasts, setToasts] = useState([]);
  const [feedFilter, setFeedFilter] = useState("all");
  useEffect(() => { const t = setInterval(() => setClock(new Date()), 1000); return () => clearInterval(t); }, []);
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && setInspect(null);
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const addToast = useCallback((msg, tone) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, msg, tone }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3200);
  }, []);
  const doBlock = useCallback((ip) => { blockIP(ip); addToast(`⛔ ${ip} contained — deny rule pushed to edge-fw-01`, "red"); }, [blockIP, addToast]);

  const FEED_FILTERS = [["all", "All"], ["attack", "⚔ Hostile"], ["auth", "🔑 Auth"], ["net", "⇄ Network"], ["ids", "🛑 IDS"]];
  const typeMatch = (e) => feedFilter === "all" ? true
    : feedFilter === "attack" ? !!e.attack
    : feedFilter === "auth" ? e.type === "auth"
    : feedFilter === "net" ? e.type === "net" || e.type === "fw"
    : e.type === "ids";
  const filtered = useMemo(() => events.filter((e) => matchQuery(e, query) && typeMatch(e)), [events, query, feedFilter]);
  const openAlerts = alerts.filter((a) => a.status === "open");
  const threatScore = Math.min(100,
    openAlerts.filter((a) => a.sev === "critical").length * 26 +
    openAlerts.filter((a) => a.sev === "high").length * 13 +
    openAlerts.filter((a) => a.sev === "medium").length * 6 +
    campaigns * 9 +
    Math.min((traffic.slice(-8).reduce((s, t) => s + t.fails, 0)) * 1.4, 18)
  );
  const topAttackers = Object.values(attackers).sort((a, b) => b.count - a.count).slice(0, 8);
  const uniqueIPs = Object.keys(attackers).length;
  const failSpark = traffic.map((t) => t.fails);
  const inbSpark = traffic.map((t) => t.inb);

  const outcomeChip = (e) => {
    const map = {
      success: e.attack ? ["BREACH", "var(--red)"] : ["OK", "var(--green)"],
      failed: ["FAIL", e.attack ? "var(--amber)" : "var(--gold)"],
      dropped: ["DROP", "var(--dim)"],
      deny: ["DENY", "var(--violet)"],
      allow: ["ALLOW", "var(--cyan)"],
      alert: ["IDS", "var(--red)"],
    };
    const [t, c] = map[e.outcome] || ["—", "var(--mut)"];
    return <span className="chip" style={{ color: c, borderColor: c, background: "rgba(0,0,0,.25)" }}>{t}</span>;
  };

  return (
    <div className={`ts-root ${paused ? "paused" : ""}`}>
      <style>{CSS}</style>

      {/* SECURE BOOT SPLASH */}
      <div className="boot" aria-hidden>
        <div className="bootlines">
          {["> THANG SENTINEL v3.1 — SECURE BOOT SEQUENCE", "> loading correlation rules SENT-001…010 ................ ✓", "> sensors online: edge-fw-01 · ids-suricata-02 · auth-03 . ✓", "> threat intelligence feeds synchronized ................. ✓", "> SOC CONSOLE ONLINE — MONITORING"].map((l, i) => (
            <div key={i} style={{ animationDelay: `${0.12 + i * 0.3}s`, color: i === 4 ? "var(--green)" : "var(--cyan)" }}>{l}</div>
          ))}
        </div>
      </div>

      {/* HEADER */}
      <div style={{ maxWidth: 1560, margin: "0 auto 14px", display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 40, height: 40, borderRadius: 9, border: "1px solid var(--cyan)", display: "grid", placeItems: "center", background: "linear-gradient(135deg,#12204A,#0A1128)", boxShadow: "0 0 18px rgba(79,216,235,.3), inset 0 0 12px rgba(79,216,235,.15)", fontSize: 19 }}>🛡️</div>
          <div>
            <div style={{ fontFamily: "var(--disp)", fontWeight: 700, fontSize: 19, letterSpacing: ".14em" }}>THANG <span style={{ color: "var(--cyan)", textShadow: "0 0 16px rgba(79,216,235,.6)" }}>SENTINEL</span></div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 9.5, color: "var(--mut)", letterSpacing: ".08em" }}>SECURITY INFORMATION &amp; EVENT MANAGEMENT · v3.1</div>
          </div>
        </div>
        <div className="searchbox">
          <span style={{ color: "var(--dim)", fontFamily: "var(--mono)", fontSize: 12 }}>⌕</span>
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder='Search events… try  status=failed   country=Russia   src=185.*   user=root' aria-label="Search events" />
          {query && <button className="iplink" style={{ color: "var(--mut)", textDecoration: "none" }} onClick={() => setQuery("")}>clear</button>}
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          {openAlerts.some((a) => a.sev === "critical") && (
            <span className="critband">⚠ CRITICAL INCIDENT — {openAlerts.filter((a) => a.sev === "critical").length} OPEN</span>
          )}
          <span style={{ display: "flex", alignItems: "center", gap: 7, fontFamily: "var(--mono)", fontSize: 11, color: paused ? "var(--amber)" : "var(--green)" }}>
            <span className="live-dot" /> {paused ? "PAUSED" : "LIVE"} · {eps.toFixed(1)} eps
          </span>
          <button className="btn" onClick={() => setPaused((p) => !p)}>{paused ? "▶ Resume" : "❚❚ Pause"}</button>
          <button className="btn" onClick={() => setSpeed((s) => (s === 1 ? 2 : s === 2 ? 4 : 1))}>{speed}× speed</button>
          <span className="mono" style={{ fontSize: 13, color: "var(--cyan)", minWidth: 70, textAlign: "right" }}>{fmtTime(clock)}</span>
        </div>
      </div>

      <div className="ts-grid">
        {/* KPI ROW */}
        {[
          { lb: "Events indexed", v: fmtNum(totals.events), sub: `${eps.toFixed(1)} events/sec`, c: "var(--cyan)", sp: inbSpark },
          { lb: "Failed logins", v: fmtNum(totals.failed), sub: "auth telemetry · 24h", c: "var(--amber)", sp: failSpark },
          { lb: "Open alerts", v: openAlerts.length, sub: `${alerts.filter((a) => a.sev === "critical" && a.status === "open").length} critical`, c: openAlerts.some((a) => a.sev === "critical") ? "var(--red)" : "var(--gold)" },
          { lb: "Hostile sources", v: uniqueIPs, sub: "unique IPs observed", c: "var(--violet)" },
          { lb: "Blocked IPs", v: blocked.length, sub: `${fmtNum(totals.dropped)} packets dropped`, c: "var(--green)" },
          { lb: "Data ingested", v: totals.dataGB.toFixed(1) + " GB", sub: "hot index · 7d retention", c: "var(--txt)" },
        ].map((k) => (
          <div className="panel col2 kpi-card" key={k.lb}>
            <div className="kpi">
              <span className="lb">{k.lb}</span>
              <div style={{ display: "flex", alignItems: "flex-end", justifyContent: "space-between", gap: 6 }}>
                <span className="v" style={{ color: k.c }}>{k.v}</span>
                {k.sp && <Spark data={k.sp.slice(-30)} color={k.c} w={72} />}
              </div>
              <span className="sub">{k.sub}</span>
            </div>
          </div>
        ))}

        {/* THREAT MAP */}
        <div className="panel col8 scanlines">
          <div className="ph">
            <h3><span className="tick">◤</span> Global threat map — live attack origin tracing</h3>
            <span className="mono" style={{ fontSize: 10, color: "var(--mut)" }}>{campaigns} active campaign{campaigns === 1 ? "" : "s"} · click a source to trace</span>
          </div>
          <ThreatMap events={events} paused={paused} onPick={setInspect} />
        </div>

        {/* GAUGE + ALERTS */}
        <div className="col4" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="panel">
            <div className="ph"><h3><span className="tick">◤</span> Threat posture</h3></div>
            <ThreatGauge score={threatScore} />
          </div>
          <div className="panel" style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <div className="ph">
              <h3><span className="tick">◤</span> Detections</h3>
              <span className="mono" style={{ fontSize: 10, color: "var(--mut)" }}>{openAlerts.length} open</span>
            </div>
            <div className="alerts" style={{ maxHeight: 330 }}>
              {alerts.length === 0 && <div style={{ color: "var(--dim)", fontSize: 12, padding: 8 }}>No detections yet. The correlation engine is watching the stream — alerts appear here the moment a rule fires.</div>}
              {alerts.slice(0, 12).map((a) => (
                <div className="alert-card" key={a.id} style={{ borderLeftColor: SEV[a.sev]?.color || "var(--green)", opacity: a.status === "open" ? 1 : 0.55 }}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4, flexWrap: "wrap" }}>
                    <span className="chip" style={{ color: SEV[a.sev]?.color, borderColor: SEV[a.sev]?.color }}>{SEV[a.sev]?.label || "INFO"}</span>
                    <span className="chip" style={{ color: "var(--violet)", borderColor: "var(--violet)" }}>{a.mitre}</span>
                    <span className="mono" style={{ fontSize: 9.5, color: "var(--dim)", marginLeft: "auto" }}>{fmtTime(a.ts)}</span>
                  </div>
                  <div style={{ fontWeight: 600, fontSize: 12.5, marginBottom: 3 }}>{a.title}</div>
                  <div style={{ fontSize: 11, color: "var(--mut)", lineHeight: 1.45 }}>{a.desc}</div>
                  <div style={{ display: "flex", gap: 8, marginTop: 7, alignItems: "center" }}>
                    {a.ip && <button className="iplink" onClick={() => setInspect(a.ip)}>{a.ip}</button>}
                    <span className="mono" style={{ fontSize: 9, color: "var(--dim)" }}>{a.rule}</span>
                    <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
                      {a.status === "open" && <button className="btn" style={{ padding: "3px 8px" }} onClick={() => ackAlert(a.id)}>Ack</button>}
                      {a.status === "open" && a.ip && !blocked.includes(a.ip) && a.mitre !== "RESPONSE" && <button className="btn danger" style={{ padding: "3px 8px" }} onClick={() => doBlock(a.ip)}>Block</button>}
                      {a.status !== "open" && <span className="chip" style={{ color: "var(--dim)", borderColor: "var(--line2)" }}>{a.status.toUpperCase()}</span>}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* LIVE EVENT STREAM */}
        <div className="panel col7" style={{ display: "flex", flexDirection: "column" }}>
          <div className="ph">
            <h3><span className="tick">◤</span> Live event pipeline {query && <span style={{ color: "var(--cyan)", textTransform: "none", letterSpacing: 0 }}>· filter: {query}</span>}</h3>
            <span className="mono" style={{ fontSize: 10, color: "var(--mut)" }}>{filtered.length}/{events.length} in buffer</span>
          </div>
          <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "8px 14px 6px", flexWrap: "wrap", borderBottom: "1px solid var(--line)" }}>
            {FEED_FILTERS.map(([k, lb]) => (
              <button key={k} className={`fchip ${feedFilter === k ? "on" : ""}`} onClick={() => setFeedFilter(k)}>{lb}</button>
            ))}
            <span style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
              {["status=failed", "src=185.*", "country=China"].map((q) => (
                <button key={q} className="qchip" onClick={() => setQuery(q)}>{q}</button>
              ))}
            </span>
          </div>
          <div className="feedhead"><span>Time</span><span>Verdict</span><span>Source</span><span>Event</span><span style={{ textAlign: "right" }}>Origin</span></div>
          <div className="feed" style={{ maxHeight: 340 }}>
            {filtered.length === 0 && <div style={{ padding: 16, color: "var(--dim)" }}>No events match this query. Try fields like status=, src=, user=, country=, service= — wildcards (*) work.</div>}
            {filtered.slice(0, 60).map((e) => (
              <div className="evrow" key={e.id}>
                <span style={{ color: "var(--dim)" }}>{fmtTime(e.ts)}</span>
                {outcomeChip(e)}
                <button className="iplink" style={{ textAlign: "left" }} onClick={() => setInspect(e.ip)}>{e.geo?.flag} {e.ip}</button>
                <span style={{ color: e.attack ? (e.outcome === "success" ? "var(--red)" : "var(--txt)") : "var(--mut)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  <span style={{ color: "var(--violet)" }}>{e.svc}</span> {e.user !== "-" && <span style={{ color: "var(--gold)" }}>{e.user}@</span>}{e.msg}
                </span>
                <span style={{ color: "var(--dim)", textAlign: "right" }}>{e.geo?.country?.slice(0, 12)}</span>
              </div>
            ))}
          </div>
        </div>

        {/* TRAFFIC + TOP ATTACKERS */}
        <div className="col5" style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <div className="panel">
            <div className="ph"><h3><span className="tick">◤</span> Network traffic — perimeter</h3></div>
            <div style={{ padding: "8px 10px 4px" }}><TrafficChart traffic={traffic} /></div>
          </div>
          <div className="panel" style={{ flex: 1 }}>
            <div className="ph"><h3><span className="tick">◤</span> Top hostile sources</h3></div>
            <table className="tbl">
              <thead><tr><th>Source IP</th><th>Origin</th><th>Threat group</th><th style={{ textAlign: "right" }}>Events</th><th /></tr></thead>
              <tbody>
                {topAttackers.map((a) => (
                  <tr key={a.ip}>
                    <td><button className="iplink" onClick={() => setInspect(a.ip)}>{a.ip}</button></td>
                    <td>{a.actor.flag} {a.actor.country}</td>
                    <td style={{ color: "var(--violet)" }}>{a.actor.group}</td>
                    <td style={{ textAlign: "right", color: "var(--amber)" }}>{a.count}</td>
                    <td style={{ textAlign: "right" }}>
                      {blocked.includes(a.ip)
                        ? <span className="chip" style={{ color: "var(--red)", borderColor: "var(--red)" }}>BLOCKED</span>
                        : <button className="btn danger" style={{ padding: "3px 8px" }} onClick={() => doBlock(a.ip)}>Block</button>}
                    </td>
                  </tr>
                ))}
                {!topAttackers.length && <tr><td colSpan="5" style={{ color: "var(--dim)", padding: 14 }}>Collecting telemetry…</td></tr>}
              </tbody>
            </table>
          </div>
        </div>

        {/* FOOTER */}
        <div className="col12" style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8, fontFamily: "var(--mono)", fontSize: 9.5, color: "var(--dim)", padding: "2px 4px" }}>
          <span>THANG SENTINEL SOC · sensors: edge-fw-01, ids-suricata-02, auth-collector-03 · all data simulated for demonstration</span>
          <span>correlation rules SENT-001…010 loaded · MITRE ATT&amp;CK v15 mappings active</span>
        </div>
      </div>

      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => <div key={t.id} className={`toast ${t.tone || ""}`}>{t.msg}</div>)}
      </div>

      {inspect && (
        <Inspector ip={inspect} events={events} attackers={attackers} blocked={blocked}
          onBlock={(ip) => doBlock(ip)} onClose={() => setInspect(null)} />
      )}
    </div>
  );
}
