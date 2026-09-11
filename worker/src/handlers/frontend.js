import { securityHeaders } from '../security.js';

export function serveFrontend() {
  const html = ` <!DOCTYPE html>

<html lang="es">

<head>

<meta charset="UTF-8">

<meta name="viewport" content="width=device-width,initial-scale=1">

<title>Astro Panel</title>

<style>

:root{--bg:#0a0a12;--surface:rgba(26,26,46,0.6);--border:rgba(240,192,64,0.1);--gold:#f0c040;--gold-dim:rgba(240,192,64,0.15);--gold-glow:rgba(240,192,64,0.3);--text:#e0e0e0;--dim:#666;--muted:#444;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--blue:#3b82f6;--r:16px;--rs:12px;--rx:8px}

*{margin:0;padding:0;box-sizing:border-box}

body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}

body::before{content:'';position:fixed;inset:-50%;background:radial-gradient(ellipse at 30% 20%,rgba(88,28,135,0.08) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(240,192,64,.03) 0%,transparent 50%);pointer-events:none;z-index:-1}

.glass{background:var(--surface);backdrop-filter:blur(20px);border:1px solid var(--border);border-radius:var(--r)}

.hidden{display:none!important}

.header{padding:18px 32px;background:rgba(10,10,18,.9);border-bottom:1px solid rgba(240,192,64,.08);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;backdrop-filter:blur(20px)}

.logo{font-weight:900;color:var(--gold);font-size:22px;letter-spacing:2px}

.logo span{font-size:10px;color:var(--dim);letter-spacing:2px}

.header-right{display:flex;align-items:center;gap:12px}

.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px rgba(34,197,94,.5)}

.container{max-width:1100px;margin:0 auto;padding:24px 32px}

.login-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center}

.login-card{width:420px;padding:48px;text-align:center}

.login-card h1{font-size:42px;font-weight:900;color:var(--gold);letter-spacing:2px}

.login-card p{color:var(--dim);margin:8px 0 32px;letter-spacing:2px;font-size:12px}

.login-card input{width:100%;padding:14px;background:#0f0f1a;border:1px solid #333;border-radius:var(--rs);color:#fff;font-family:monospace;margin-bottom:12px}

.login-card input:focus{outline:none;border-color:var(--gold)}

.login-card button{width:100%;padding:14px;background:linear-gradient(135deg,var(--gold),#e6a800);color:#000;border:none;border-radius:var(--rs);font-weight:700;cursor:pointer}

.login-card button:hover{opacity:.9}

#loginMsg{color:var(--red);font-size:13px;min-height:18px;margin-top:12px}

.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}

.stat{padding:20px;text-align:center}

.stat b{font-size:28px;display:block;color:var(--gold)}

.stat div{color:var(--dim);font-size:11px;margin-top:4px}

.pending{border-color:rgba(245,158,11,.3);background:rgba(245,158,11,.04)}

.card{padding:20px;margin-bottom:20px}

.card h3{color:var(--gold);margin-bottom:12px;font-size:14px}

.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}

.row input{flex:1;min-width:180px;padding:10px;background:#0f0f1a;border:1px solid #333;border-radius:var(--rx);color:#fff;font-family:monospace}

.pill{padding:8px 14px;border-radius:var(--rx);border:1px solid #333;background:transparent;color:var(--dim);cursor:pointer;font-size:12px}

.pill.active{border-color:var(--gold);color:var(--gold);background:var(--gold-dim)}

.btn{padding:8px 16px;border-radius:var(--rx);border:none;cursor:pointer;font-weight:600;font-size:13px}

.btn-gold{background:var(--gold);color:#000}

.btn-ghost{background:#222;color:#aaa;border:1px solid #333}

.btn-green{background:var(--green);color:#fff}

.btn-red{background:var(--red);color:#fff}

.btn-dark{background:#111;color:#f87171;border:1px solid #7f1d1d}

table{width:100%;border-collapse:collapse;font-size:13px}

th{color:var(--dim);text-align:left;padding:8px;border-bottom:1px solid #333;font-size:11px}

td{padding:10px 8px;border-bottom:1px solid #222}

.badge{padding:2px 8px;border-radius:10px;font-size:11px}

.badge-active{background:rgba(34,197,94,.15);color:var(--green)}

.badge-pending{background:rgba(245,158,11,.15);color:var(--amber)}

.badge-revoked{background:rgba(239,68,68,.15);color:var(--red)}

.mono{font-family:monospace;font-size:11px;color:var(--gold)}

#toast{position:fixed;top:20px;right:20px;z-index:99}

.toast{padding:12px 18px;border-radius:8px;color:#fff;margin-bottom:8px;min-width:250px}

.toast.ok{background:#166534}

.toast.err{background:#7f1d1d}

@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}.container{padding:16px}}

</style>

</head>

<body>

<div id="loginView" class="login-wrap">

  <div class="login-card glass">

    <h1>ASTRO</h1><span id="alertBadge" title="Alertas de seguridad sin revisar" style="display:none;background:var(--red);color:#fff;border-radius:10px;padding:2px 9px;font-size:11px;margin-left:12px;vertical-align:middle;cursor:pointer" onclick="toggleAlerts()"></span><div id="alertBox" style="display:none;background:var(--surface);border:1px solid var(--border);border-radius:12px;margin:12px 0;max-height:320px;overflow-y:auto"><div id="alertList"></div></div>

    <p>LICENSE CONTROL</p>

    <input id="keyInput" type="password" placeholder="Admin API Key" onkeydown="if(event.key==='Enter')login()">

    <button class="btn-gold" onclick="login()" id="loginBtn" style="width:100%;padding:14px">Access Panel</button>

    <div id="loginMsg"></div>

  </div>

</div>



<div id="dashView" class="hidden">

  <div class="header">

    <div class="logo">ASTRO <span>PANEL</span></div>

    <div class="header-right"><span class="dot"></span><button class="btn-ghost" onclick="logout()" style="padding:6px 12px">Logout</button></div>

  </div>

  <div class="container">

    <div class="stats">

      <div class="stat glass"><b id="sTotal">0</b><div>TOTAL</div></div>

      <div class="stat glass"><b id="sActive" style="color:var(--green)">0</b><div>ACTIVE</div></div>

      <div class="stat glass"><b id="sPending" style="color:var(--amber)">0</b><div>PENDING</div></div>

      <div class="stat glass"><b id="sRevoked" style="color:var(--red)">0</b><div>REVOKED</div></div>

    </div>



    <div id="pendingBox" class="card glass pending hidden">

      <h3 style="color:var(--amber)">Pending Approvals <span id="pendingCount"></span></h3>

      <div id="pendingList"></div>

    </div>



    <div class="card glass">

      <h3>Create License</h3>

      <div class="row">

        <input id="newKey" placeholder="License Key">

        <button class="btn-ghost" onclick="genKey()">Generate</button>

        <select id="tierSel" style="background:#0f0f1a;color:#fff;border:1px solid #333;border-radius:8px;padding:8px">

          <option value="2">Premium</option><option value="1" selected>Basic</option><option value="0">Trial</option>

        </select>

        <button class="btn btn-gold" onclick="createLic()">Create</button>

      </div>

    </div>



    <div class="card glass">

      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">

        <h3>All Licenses</h3>

        <input id="search" placeholder="Search..." style="padding:8px;background:#0f0f1a;border:1px solid #333;border-radius:8px;color:#fff" oninput="filterTable()">

      </div>

      <div style="overflow-x:auto">

        <table>

          <thead><tr><th>Key</th><th>HWID</th><th>Tier</th><th>Status</th><th>Expires</th><th>Actions</th></tr></thead>

          <tbody id="licTable"><tr><td colspan="6" style="text-align:center;color:#666">No data</td></tr></tbody>

        </table>

      </div>

    </div>

  </div>

</div>



<div id="toast"></div>



<script>

const API=location.origin;

let TOKEN=localStorage.getItem('astro_session')||'';

let TIERS={0:'Trial',1:'Basic',2:'Premium'};



async function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}

async function toast(m,t='ok'){const c=document.getElementById('toast');const d=document.createElement('div');d.className='toast '+(t==='ok'?'ok':'err');d.textContent=m;c.appendChild(d);setTimeout(()=>d.remove(),3000)}

async function showDash(){document.getElementById('loginView').classList.add('hidden');document.getElementById('dashView').classList.remove('hidden')}

function showLogin(){document.getElementById('dashView').classList.add('hidden');document.getElementById('loginView').classList.remove('hidden')}



async function login(){

  const key=document.getElementById('keyInput').value.trim();

  const msg=document.getElementById('loginMsg');

  const btn=document.getElementById('loginBtn');

  if(!key){msg.textContent='Enter key';return}

  msg.textContent='Authenticating...';btn.disabled=true;

  try{

    const r=await fetch(API+'/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({admin_key:key})});

    const d=await r.json();

    if(!r.ok||d.error){msg.textContent=d.error||'Login failed';btn.disabled=false;return}

    TOKEN=d.session_token;localStorage.setItem('astro_session',TOKEN);

    window._lastPendingKeys=null;

    showDash();toast('Welcome');loadData();

  }catch(e){msg.textContent='Connection failed';}

  btn.disabled=false;

}

function logout(){TOKEN='';localStorage.removeItem('astro_session');showLogin()}

function genKey(){const c='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';const buf=new Uint32Array(16);crypto.getRandomValues(buf);let k='';for(let i=0;i<16;i++)k+=c[buf[i]%c.length];document.getElementById('newKey').value=k.slice(0,4)+'-'+k.slice(4,8)+'-'+k.slice(8,12)+'-'+k.slice(12,16)+'-000000000000'}



async function loadData(){

  try{

    const r=await fetch(API+'/api/stats',{headers:{'X-Session-Token':TOKEN}});

    if(r.status===401){toast('Session expired','err');logout();return}

    const s=await r.json();

    if(s.error){toast(s.error,'err');return}

    const prevPending = window._lastPendingKeys ? new Set(window._lastPendingKeys) : null;

    document.getElementById('sTotal').textContent=s.total_licenses||0;

    document.getElementById('sActive').textContent=s.active_licenses||0;

    document.getElementById('sPending').textContent=s.pending_licenses||0;

    document.getElementById('sRevoked').textContent=s.revoked_licenses||0;

    const pending=(s.licenses||[]).filter(l=>l.status==='pending'&&!l.is_revoked);

    const pendingKeys = pending.map(l=>l.license_key);

    if(prevPending && pending.length){

      const newcomers = pending.filter(l=>!prevPending.has(l.license_key));

      newcomers.forEach(l=>{

        let host='?'; try{const hw=JSON.parse(l.hardware_info||'{}'); host=hw.hostname||hw.host||l.client_ip||'?';}catch{}

        toast('Nueva solicitud: '+l.license_key.slice(0,14)+'... PC '+host,'ok');

        if('vibrate' in navigator) try{navigator.vibrate(200)}catch{}

        try{ const a=new Audio('data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAAAAA=='); a.volume=0.6; a.play().catch(()=>{});}catch{}

      });

    }

    window._lastPendingKeys = pendingKeys;

    const box=document.getElementById('pendingBox');

    async function renderHw(hwStr, clientIp, clientCountry, fallbackHwid){

      let hw={}; try{hw=JSON.parse(hwStr||'{}')}catch{}

      const hasReal = !!(hw.hostname||hw.host||hw.cpu||hw.gpu||hw.motherboard||hw.peripherals);

      const ip = hw._server_ip || clientIp || 'unknown';

      const country = hw._server_country || clientCountry || '';

      let host = hw.hostname || hw.host || hw.computer_name || hw.machineHostName || '';

      const user = hw.username || hw.user || hw.windows_user || '';

      // Si no hay hostname pero si hay IP/MAC/host alternativo, no mostrar unknown

      const hostLabel = host || (hasReal ? 'sin-nombre' : (clientIp ? 'PC '+clientIp : 'PC desconocido'));

      const isUnknown = !host && !hasReal;

      const cpu = hw.cpu || hw.processor_name || hw.processorName || hw.cpu_name || '';

      const cores = hw.cores || hw.processor_cores || hw.cpu_cores || '';

      const ram = hw.ram_gb || hw.total_ram_gb || hw.ram || (hw.totalRAMBytes? (hw.totalRAMBytes/1073741824).toFixed(1)+'GB':'');

      const gpu = hw.gpu || hw.gpu_name || hw.gpuName || '';

      const vram = hw.gpu_vram_gb || hw.gpuVRAMBytes || '';

      const disk = hw.disk_serial || hw.diskSerial || hw.disk || '';

      const mobo = hw.motherboard || hw.baseboard_serial || hw.mobo_serial || hw.motherboard_serial || '';

      const bios = hw.bios_serial || hw.biosSerial || hw.bios_version || hw.biosVersion || '';

      const os = hw.os || hw.os_version || hw.osVersion || hw.windows_version || '';

      const mac = hw.mac || hw.network_mac || hw.networkMAC || hw.mac_address || '';

      const localIp = hw.local_ip || hw.localIp || hw.private_ip || '';

      const tpmMan = hw.tpm_manufacturer || hw.tpmManufacturer || '';

      const tpmHash = hw.tpm_serial_hash || hw.tpm_hash || hw.tpmSerial || hw.tpm_serial || '';

      const tpmPresent = hw.tpm_present!==undefined? hw.tpm_present : (tpmMan? true : '');

      const perifs = hw.peripherals || hw.usb_devices || hw.perifericos || hw.devices || [];

      const monitors = hw.monitors || [];

      let html='';

      // Banner si cliente antiguo sin hw_collect

      if(isUnknown && hw._note){

        html+='<div style="background:#7f1d1d;padding:6px 8px;border-radius:6px;font-size:11px;margin-bottom:6px;border:1px solid #991b1b;color:#fecaca">Este AstroLoader es antiguo - no envio datos de PC. Actualiza el .exe para ver hostname/componentes. IP capturada: '+esc(ip)+'</div>';

      } else if(isUnknown){

        html+='<div style="background:#451a03;padding:6px 8px;border-radius:6px;font-size:11px;margin-bottom:6px;border:1px solid #78350f;color:#fde68a">PC reporto datos minimos - actualiza AstroLoader.exe (hw_collect). IP: '+esc(ip)+'</div>';

      }

      html+='<div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 8px">';

      html+='<span style="background:#1f2937;padding:4px 8px;border-radius:999px;font-size:11px;border:1px solid #374151">IP: <b style="color:#93c5fd">'+esc(ip)+'</b>'+(country?' '+esc(country):'')+'</span>';

      html+='<span style="background:'+(isUnknown?'#1f2937':'#1f2937')+';padding:4px 8px;border-radius:999px;font-size:11px;border:1px solid '+(isUnknown?'#f59e0b':'#374151')+'">PC: <b style="color:'+(isUnknown?'#fbbf24':'#f9a8d4')+'">'+esc(hostLabel)+'</b>'+(user?' ('+esc(user)+')':'')+'</span>';

      if(hw._collected_at) html+='<span style="background:#1f2937;padding:4px 8px;border-radius:999px;font-size:11px;color:#9ca3af">'+esc(new Date(hw._collected_at).toLocaleString())+'</span>';

      html+='</div>';

      if(fallbackHwid) html+='<div style="color:#666;font-size:11px;margin:4px 0">HWID: '+esc(fallbackHwid.slice(0,16))+'... &middot; <span style="color:#9ca3af">local IP: '+esc(localIp||'-')+' &middot; MAC: '+esc(mac||'-')+'</span></div>';

      html+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:6px;margin:8px 0;font-size:11px">';

      if(cpu) html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">CPU</div><div style="color:#e5e7eb;word-break:break-word">'+esc(cpu)+(cores?' ('+esc(String(cores))+' cores)':'')+'</div></div>';

      if(gpu) html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">GPU</div><div style="color:#e5e7eb;word-break:break-word">'+esc(gpu)+(vram?' '+esc(String(vram)):'')+'</div></div>';

      if(ram || disk) html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">RAM / Disk</div><div style="color:#e5e7eb">'+esc(String(ram||'-'))+' &middot; '+esc(String(disk||'-').substring(0,24))+'</div></div>';

      if(mobo || bios) html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">Board / BIOS</div><div style="color:#e5e7eb;word-break:break-word">'+esc(mobo||'-')+'<br>'+esc(bios||'')+'</div></div>';

      if(os) html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">OS</div><div style="color:#e5e7eb">'+esc(os)+'</div></div>';

      if(tpmMan||tpmHash||tpmPresent!=='') html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222"><div style="color:#9ca3af;font-size:10px">TPM</div><div style="color:#e5e7eb">'+esc(tpmMan||'unknown')+(tpmHash?' &middot; '+esc(String(tpmHash).substring(0,16))+'...':'')+(tpmPresent===true||tpmPresent==='true'?' &middot; present': tpmPresent===false?' &middot; absent':'')+'</div></div>';

      html+='</div>';

      if((perifs&&perifs.length)||(monitors&&monitors.length)){

        html+='<div style="background:#0a0a12;padding:8px;border-radius:6px;border:1px solid #222;margin:6px 0"><div style="color:#9ca3af;font-size:10px;margin-bottom:4px">Perifericos '+(perifs.length?'('+perifs.length+')':'')+'</div><div style="color:#d1d5db;display:flex;flex-wrap:wrap;gap:4px">';

        perifs.slice(0,20).forEach(p=>{ html+='<span style="background:#111827;padding:3px 6px;border-radius:4px;font-size:10px;border:1px solid #1f2937">'+esc(typeof p==='string'? p : JSON.stringify(p))+'</span>' });

        monitors.slice(0,10).forEach(m=>{ html+='<span style="background:#1e1b4b;padding:3px 6px;border-radius:4px;font-size:10px;border:1px solid #312e81">'+esc(typeof m==='string'? m : m.name||JSON.stringify(m))+'</span>' });

        html+='</div></div>';

      }

      if(isUnknown && !perifs.length) html+='<div style="color:#6b7280;font-size:10px;margin:4px 0">Sin datos de hardware - el cliente no envio hostname/componentes. Pide al usuario actualizar AstroLoader.exe.</div>';

      html+='<details style="margin-top:6px"><summary style="cursor:pointer;color:#6b7280;font-size:10px">Ver JSON crudo</summary><pre style="background:#080810;padding:8px;border-radius:6px;font-size:10px;max-height:160px;overflow:auto;margin:6px 0;white-space:pre-wrap;word-break:break-word">'+esc(JSON.stringify(hw,null,2))+'</pre></details>';

      return html;

    }

    if(pending.length){box.classList.remove('hidden');document.getElementById('pendingCount').textContent='('+pending.length+')';document.getElementById('pendingList').innerHTML=pending.map(l=>'<div style="border:1px solid #333;padding:12px;border-radius:8px;margin-bottom:8px;background:#111827"><div style="color:#f0c040;font-family:monospace;font-size:12px;display:flex;justify-content:space-between;align-items:center">'+esc(l.license_key)+' <button class="btn-ghost" style="padding:2px 8px;font-size:11px" onclick="navigator.clipboard.writeText(\''+esc(l.license_key)+'\')">Copy</button></div>'+renderHw(l.hardware_info, l.client_ip, l.client_country, l.hwid_hash)+'<div style="display:flex;gap:8px;margin-top:8px"><button class="btn-green" style="padding:6px 12px" onclick="approve(\''+esc(l.license_key)+'\')">Activar - ligar a PC</button> <button class="btn-red" style="padding:6px 12px" onclick="reject(\''+esc(l.license_key)+'\')">Reject</button></div></div>').join('')} else box.classList.add('hidden');

    const tbody=document.getElementById('licTable');

    const all=s.licenses||[];

    if(!all.length){tbody.innerHTML='<tr><td colspan="6" style="text-align:center;color:#666">No licenses</td></tr>';return}

    tbody.innerHTML=all.map(l=>{

      const st=l.is_revoked?'revoked':(l.status||'active');

      const hwidShort=l.hwid_hash?esc(l.hwid_hash.slice(0,12))+'...':'<span style="color:#666">not bound</span>';

      const isActive = st==='active';

      const isPending = st==='pending';

      return '<tr><td class="mono" style="color:#f0c040">'+esc(l.license_key)+'</td><td class="mono" style="color:#666">'+hwidShort+'</td><td><span class="badge badge-'+st+'">'+TIERS[l.tier||0]+'</span></td><td><span class="badge badge-'+st+'">'+st+'</span></td><td style="color:#666;font-size:11px">'+(l.expires_at?new Date(l.expires_at).toLocaleDateString():'-')+'</td><td style="display:flex;gap:4px;flex-wrap:wrap">'+(isPending?'<button class="btn-green" style="padding:4px 8px;font-size:11px" onclick="approve(\''+esc(l.license_key)+'\')">Activar</button>':'')+(isActive?'<button class="btn-red" style="padding:4px 8px;font-size:11px" onclick="revoke(\''+esc(l.license_key)+'\')">Revoke</button> ':'')+'<button class="btn-ghost" style="padding:4px 8px;font-size:11px" onclick="removeLic(\''+esc(l.license_key)+'\')">Remove</button><button class="btn-dark" style="padding:4px 8px;font-size:11px" onclick="autokill(\''+esc(l.license_key)+'\')">Autokill</button></td></tr>';

    }).join('');

  // Security alerts poll (clone detection etc.)

  try{

    const ar=await fetch(API+'/api/alerts?unseen=1&limit=20',{headers:{'X-Session-Token':TOKEN}});

    if(ar.ok){

      const aj=await ar.json();

      const list=aj.alerts||[];

      const badge=document.getElementById('alertBadge');

      if(badge){badge.textContent=list.length;badge.style.display=list.length?'inline-block':'none';}

      const prevAlerts=window._lastAlertIds||null;

      const newcomersA=list.filter(a=>!prevAlerts||!prevAlerts.has(a.id));

      if(prevAlerts && newcomersA.length){

        newcomersA.slice(0,3).forEach(a=>toast('[ALERT] '+a.alert_type+' '+(a.license_key||'').slice(0,14),'err'));

        try{const a2=new Audio('data:audio/wav;base64,UklGRigAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQQAAAAAAA==');a2.volume=0.9;a2.play().catch(()=>{});}catch{}

      }

      window._lastAlertIds=new Set(list.map(a=>a.id));

    }

  }catch(_e){}



  }catch(e){toast('Load failed','err')}

}

async function createLic(){

  const k=document.getElementById('newKey').value.trim();if(!k){toast('Enter key','err');return}

  const tier=parseInt(document.getElementById('tierSel').value);

  const r=await fetch(API+'/api/create',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k,tier})});

  const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Creada - esperando que el usuario la ponga en su Astro');document.getElementById('newKey').value='';loadData()}

}

async function approve(k){const r=await fetch(API+'/api/approve',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Activada y ligada a PC - quedara cacheada');loadData()}}

async function reject(k){const reason=prompt('Reason:','');if(reason===null)return;const r=await fetch(API+'/api/reject',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k,reason})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Rejected');loadData()}}

async function revoke(k){if(!confirm('Revoke '+k+'?'))return;const r=await fetch(API+'/api/kill',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Revoked');loadData()}}

async function delLic(k){if(!confirm('DELETE '+k+'?'))return;const r=await fetch(API+'/api/delete',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Deleted');loadData()}}

async function removeLic(k){if(!confirm('Remove '+k+'? Borra de DB y limpia telemetry/sesiones'))return;const r=await fetch(API+'/api/remove',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Removed');loadData()}}

async function autokill(k){if(!confirm('AUTOKILL '+k+'? Eliminara TODO rastro de Astro en el PC del usuario en su proximo heartbeat (borra %LOCALAPPDATA%\\Astro, %TEMP%\\astro_app, logs, prefetch y se auto-borra). Esta accion borra tambien la licencia del servidor. Continuar?'))return;const r=await fetch(API+'/api/autokill',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:JSON.stringify({license_key:k})});const d=await r.json();if(d.error)toast(d.error,'err');else{toast('Autokill ejecutado - cliente se wipeara en proximo heartbeat');loadData()}}

function filterTable(){const q=document.getElementById('search').value.toLowerCase();document.querySelectorAll('#licTable tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':'none')}



// Auto-login: verify token before showing dash

let _pollTimer=null;



let _alertsVisible=false;

async function toggleAlerts(){

  _alertsVisible=!_alertsVisible;

  const box=document.getElementById('alertBox');

  if(!_alertsVisible){box.style.display='none';return}

  box.style.display='block';

  const ar=await fetch(API+'/api/alerts?limit=50',{headers:{'X-Session-Token':TOKEN}});

  const aj=await ar.json();

  const list=aj.alerts||[];

  document.getElementById('alertList').innerHTML=list.length?list.map(a=>{

    const col=a.severity==='high'?'var(--red)':(a.severity==='low'?'var(--dim)':'var(--gold)');

    return '<div style="padding:10px;border-bottom:1px solid #222"><b style="color:'+col+'">'+esc(a.alert_type)+'</b> <span style="color:#666;font-size:11px">'+(a.created_at||'')+'</span><br><span class="mono" style="font-size:11px;color:#999">'+esc((a.license_key||'-')+' | '+a.ip_address+' | '+(a.country||''))+'</span>'+(a.details?'<br><span style="font-size:11px;color:#777">'+esc(a.details.substring(0,160))+'</span>':'')+'</div>';

  }).join(''):'<div style="padding:16px;color:#666">Sin alertas</div>';

  fetch(API+'/api/alerts/seen',{method:'POST',headers:{'Content-Type':'application/json','X-Session-Token':TOKEN},body:'{}'}).catch(()=>{});

}



function startPolling(){ if(_pollTimer) clearInterval(_pollTimer); _pollTimer=setInterval(()=>{ if(!document.getElementById('dashView').classList.contains('hidden') && TOKEN) loadData(); }, 3000); document.addEventListener('visibilitychange', ()=>{ if(document.visibilityState==='visible' && !document.getElementById('dashView').classList.contains('hidden') && TOKEN) loadData(); });}

function stopPolling(){ if(_pollTimer){ clearInterval(_pollTimer); _pollTimer=null; } }

const _origShowDash = showDash;

showDash = function(){ _origShowDash(); startPolling(); };

const _origLogout = logout;

logout = function(){ stopPolling(); window._lastPendingKeys=null; _origLogout(); };

if(TOKEN){

  fetch(API+'/api/stats',{headers:{'X-Session-Token':TOKEN}}).then(r=>{

    if(r.ok) return r.json().then(s=>{if(!s.error){showDash();loadData();} else {TOKEN='';localStorage.removeItem('astro_session')}});

    else {TOKEN='';localStorage.removeItem('astro_session')}

  }).catch(()=>{TOKEN='';localStorage.removeItem('astro_session')});

}

</script>

</body>

</html> `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8', ...securityHeaders() } });
}
