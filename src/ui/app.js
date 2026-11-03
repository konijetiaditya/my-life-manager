
import { Vault, FILE_ID_PATTERN, VaultDamagedError } from '../security/vault';
import { getSecretStore } from '../platform/secretStore';
import { validateUpload, sniff, mimeFor } from '../security/files';
import { parseState } from '../security/schema';
import { repairCollections } from '../security/repair';
import { createBackup, readBackup, checkBackupPassword, BackupError } from '../security/backup';
import { pinWeakness } from '../security/pinPolicy';
import { biometricAvailable, confirmBiometric } from '../platform/biometric';
import { watchLifecycle, minimizeApp } from '../platform/lifecycle';
import { notificationPermission, replaceScheduled, cancelAllScheduled, sendTest } from '../platform/notify';
import { deliverBackup } from '../platform/share';
import { isNative } from '../platform/env';

const vault=new Vault(getSecretStore());
const ENV={bio:false};
const $=(s,el=document)=>el.querySelector(s), $$=(s,el=document)=>Array.from(el.querySelectorAll(s));
const esc=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const uid=()=>{const a=new Uint8Array(6);crypto.getRandomValues(a);return Array.from(a,b=>b.toString(36).padStart(2,'0')).join('').slice(0,10)};
const pad=n=>String(n).padStart(2,'0');

/* ---------- dates ---------- */
let T0=new Date();T0.setHours(0,0,0,0);
const iso=d=>d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate());
const pd=s=>{const[a,b,c]=s.split('-').map(Number);return new Date(a,b-1,c)};
let TODAY=iso(T0);function refreshToday(){const n=new Date();n.setHours(0,0,0,0);if(iso(n)!==TODAY){T0=n;TODAY=iso(n);UI.bills.month=TODAY.slice(0,7);UI.bills.year=TODAY.slice(0,4)}}
const addD=(s,n)=>{const d=pd(s);d.setDate(d.getDate()+n);return iso(d)};
const addM=(s,n)=>{const d=pd(s);const day=d.getDate();d.setDate(1);d.setMonth(d.getMonth()+n);const last=new Date(d.getFullYear(),d.getMonth()+1,0).getDate();d.setDate(Math.min(day,last));return iso(d)};
const diff=(a,b)=>Math.round((pd(a)-pd(b))/864e5);
const fd=s=>s?pd(s).toLocaleDateString('en-IN',{day:'numeric',month:'short',year:'numeric'}):'—';
const fds=s=>s?pd(s).toLocaleDateString('en-IN',{day:'numeric',month:'short'}):'—';
const stepRec=(s,rec,custom,dir=1)=>{
  switch(rec){case 'daily':return addD(s,dir);case 'weekly':return addD(s,7*dir);case 'monthly':return addM(s,dir);
  case 'quarterly':return addM(s,3*dir);case 'annual':return addM(s,12*dir);case 'custom':return addD(s,(custom||30)*dir);default:return s}};
const monthLabel=k=>{const[y,m]=k.split('-').map(Number);return new Date(y,m-1,1).toLocaleDateString('en-IN',{month:'short',year:'numeric'})};
const monthShort=k=>{const[y,m]=k.split('-').map(Number);return new Date(y,m-1,1).toLocaleDateString('en-IN',{month:'short'})};
const ago=ts=>{const m=Math.round((Date.now()-ts)/6e4);if(m<1)return 'Just now';if(m<60)return m+' min ago';const h=Math.round(m/60);if(h<24)return h+' h ago';const d=Math.round(h/24);return d===1?'Yesterday':d+' days ago'};

/* ---------- state ---------- */
let S=null;
const CUR={INR:['₹','en-IN'],USD:['$','en-US'],EUR:['€','en-IE'],GBP:['£','en-GB'],AED:['AED ','en-US']};
const money=(n,d=0)=>{const c=CUR[S.settings.currency]||CUR.INR;const v=Math.abs(n).toLocaleString(c[1],{minimumFractionDigits:d,maximumFractionDigits:d});return (n<0?'−':'')+c[0]+v};
const sgn=n=>(n>0?'+':n<0?'−':'')+money(Math.abs(n));
const pc=n=>(n>0?'+':n<0?'−':'')+Math.abs(n).toFixed(1)+'%';
const cmp=n=>{const a=Math.abs(n);if(S.settings.currency==='INR'){if(a>=1e7)return (n/1e7).toFixed(1)+'Cr';if(a>=1e5)return (n/1e5).toFixed(1)+'L'}else if(a>=1e6)return (n/1e6).toFixed(1)+'M';return a>=1e3?(n/1e3).toFixed(a>=1e4?0:1)+'k':String(Math.round(n))};
const wt=g=>g>=1000?(g/1000).toLocaleString('en-IN',{maximumFractionDigits:3})+' kg':g.toLocaleString('en-IN',{maximumFractionDigits:2})+' g';
const sum=(a,f)=>a.reduce((x,y)=>x+f(y),0);
let saveChain=Promise.resolve(),notifTimer=null,saveWarned=false;
function persist(){if(!S)return;const json=JSON.stringify(S);
  saveChain=saveChain.then(()=>vault.save(json)).then(()=>{saveWarned=false}).catch(()=>{if(!saveWarned){saveWarned=true;toast('Could not save your last change. Free some storage space and try again.')}});
  clearTimeout(notifTimer);notifTimer=setTimeout(()=>{notifTimer=null;syncNotifs()},800)}
function log(text,type){S.activity.unshift({id:uid(),ts:Date.now(),text,type:type||'edit'});S.activity=S.activity.slice(0,40)}

/* ---------- empty state, settings and loading ---------- */
const COLL=['bills','ins','inv','gold','silver','docs','rem','loans'];
const DEFAULT_SETTINGS=()=>({name:'there',currency:'INR',bio:false,autoLock:5,leaveLock:60,hideNotif:true,nBills:true,nIns:true,nDocs:true,nSip:true,adv:3,notif:false});
const emptyState=name=>{const s={v:1,settings:{...DEFAULT_SETTINGS(),name:(name||'there').slice(0,30)},activity:[]};COLL.forEach(c=>{s[c]=[]});return s};
function cleanSettings(raw){const d=DEFAULT_SETTINGS(),r=raw&&typeof raw==='object'?raw:{},o={};
  for(const k of Object.keys(d)){const dv=d[k],v=r[k];
    if(typeof dv==='boolean')o[k]=typeof v==='boolean'?v:dv;
    else if(typeof dv==='number')o[k]=typeof v==='number'&&isFinite(v)?v:dv;
    else o[k]=typeof v==='string'?v:dv}
  if(!CUR[o.currency])o.currency='INR';
  if(![0,1,5,15].includes(o.autoLock))o.autoLock=5;
  if(![0,60,300].includes(o.leaveLock))o.leaveLock=60;
  if(![1,3,5,7].includes(o.adv))o.adv=3;
  o.name=o.name.trim().slice(0,30)||'there';
  return o}
/** Turns parsed (already sanitised) data into a state the screens can safely use. */
function adopt(parsed){const st={v:1,settings:cleanSettings(parsed.settings)};COLL.forEach(c=>{st[c]=parsed[c]});
  const r=repairCollections(st);
  st.activity=(Array.isArray(parsed.activity)?parsed.activity:[]).filter(a=>a&&typeof a.text==='string'&&typeof a.ts==='number'&&isFinite(a.ts)).slice(0,40)
    .map(a=>({id:String(a.id||uid()).slice(0,40),ts:a.ts,text:a.text.slice(0,200),type:['edit','pay','inv','gold','silver','doc','del'].includes(a.type)?a.type:'edit'}));
  return {state:st,dropped:r.dropped}}
/* ---------- attached files (always encrypted in the vault) ---------- */
const fileIdsOf=r=>Object.entries(r).filter(([k,v])=>k!=='id'&&k.endsWith('_id')&&typeof v==='string'&&FILE_ID_PATTERN.test(v)).map(([,v])=>v);
const fileRef=(name,id)=>!name?'None':(id&&FILE_ID_PATTERN.test(id)?`${esc(name)} <button class="link" data-a="viewFile" data-id="${id}" data-n="${esc(name)}" style="margin-left:6px">${ic('eye',14)}Open</button>`:esc(name));
let viewerUrls=[],viewerPdf=null;
function releaseViewer(){viewerUrls.forEach(u=>URL.revokeObjectURL(u));viewerUrls=[];if(viewerPdf){try{viewerPdf.destroy()}catch(e){}viewerPdf=null}}
async function showPdf(bytes,body){
  const pdfjs=await import('pdfjs-dist/legacy/build/pdf.min.mjs');
  const w=await import('pdfjs-dist/legacy/build/pdf.worker.min.mjs?url');
  pdfjs.GlobalWorkerOptions.workerSrc=w.default;
  const doc=await pdfjs.getDocument({data:bytes.slice(),isEvalSupported:false,enableXfa:false,disableAutoFetch:true,useSystemFonts:false,
    cMapUrl:'./pdfjs/cmaps/',cMapPacked:true,standardFontDataUrl:'./pdfjs/standard_fonts/',wasmUrl:'./pdfjs/wasm/'}).promise;
  viewerPdf=doc;body.replaceChildren();
  const n=Math.min(doc.numPages,30),width=Math.min(body.clientWidth||340,900);
  for(let i=1;i<=n;i++){if(viewerPdf!==doc)return;
    const pg=await doc.getPage(i),v0=pg.getViewport({scale:1}),vp=pg.getViewport({scale:(width/v0.width)*Math.min(2,window.devicePixelRatio||1)});
    const cv=document.createElement('canvas');cv.width=vp.width;cv.height=vp.height;cv.setAttribute('role','img');cv.setAttribute('aria-label','Page '+i);body.appendChild(cv);
    await pg.render({canvasContext:cv.getContext('2d'),viewport:vp,canvas:cv}).promise}
  if(doc.numPages>n){const p=document.createElement('p');p.className='muted small';p.textContent=`Showing the first ${n} of ${doc.numPages} pages.`;body.appendChild(p)}}
async function viewFile(id,name){
  if(!FILE_ID_PATTERN.test(id||'')){toast('This file is not stored in the app.');return}
  openModal(head(name||'File')+`<div id="vbody" class="viewer"><p class="muted">Decrypting…</p></div><div class="mf"><button class="btn" data-a="close2">Close</button></div>`,2);
  try{const bytes=await vault.getFile(id),kind=sniff(bytes),body=$('#vbody');if(!body)return;
    if(kind==='png'||kind==='jpg'){const url=URL.createObjectURL(new Blob([bytes],{type:mimeFor(kind)}));viewerUrls.push(url);const im=new Image();im.alt=name||'Image';im.src=url;body.replaceChildren(im)}
    else if(kind==='pdf')await showPdf(bytes,body);
    else body.textContent='This file type cannot be shown.'}
  catch(e){const b=$('#vbody');if(b)b.textContent='This file could not be opened. It may be damaged.'}}
const busy=m=>{const b=$('#busy');if(!b)return;if(m){$('p',b).textContent=m;b.hidden=false}else b.hidden=true};

/* ---------- icons ---------- */
const IC={
home:'<path d="M3 11l9-8 9 8"/><path d="M5 10v10h5v-6h4v6h5V10"/>',
wallet:'<path d="M3 7h15a3 3 0 013 3v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/><path d="M3 7l12-3v3"/><circle cx="17" cy="14" r="1.2"/>',
shield:'<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
trend:'<path d="M3 17l6-6 4 4 8-8"/><path d="M15 7h6v6"/>',
coin:'<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5h4a1.5 1.5 0 010 3h-3a1.5 1.5 0 000 3h4M12 7v2M12 15.5v2"/>',
pie:'<circle cx="12" cy="12" r="9"/><path d="M12 3v9l7 5"/>',
folder:'<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>',
bell:'<path d="M6 16v-5a6 6 0 1112 0v5l2 2H4l2-2z"/><path d="M10 21h4"/>',
gear:'<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2"/>',
lock:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
plus:'<path d="M12 5v14M5 12h14"/>',
edit:'<path d="M4 20h4L19 9l-4-4L4 16v4z"/>',
trash:'<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
search:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
cal:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
chev:'<path d="M9 6l6 6-6 6"/>',
check:'<path d="M5 12l5 5 9-10"/>',
alert:'<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4M12 17v.5"/>',
more:'<circle cx="5" cy="12" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="19" cy="12" r="1.5"/>',
eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
finger:'<path d="M5 11a7 7 0 0114 0M8 20c0-3 0-6 4-6s4 3 4 6M12 10v4M3.5 15c.5-1.5.6-2.6.8-4M20.5 15c-.5-1.5-.6-2.6-.8-4"/>',
x:'<path d="M6 6l12 12M18 6L6 18"/>',
down:'<path d="M12 4v12M7 11l5 5 5-5M5 20h14"/>',
up:'<path d="M12 16V4M7 9l5-5 5 5M5 20h14"/>',
info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
file:'<path d="M6 3h8l4 4v14H6V3z"/><path d="M14 3v4h4"/>',
cloud:'<path d="M7 18a4 4 0 010-8 5.5 5.5 0 0110.6 1.5A3.3 3.3 0 0117 18H7z"/>',
refresh:'<path d="M20 11a8 8 0 00-14-4M4 4v4h4M4 13a8 8 0 0014 4M20 20v-4h-4"/>'
};
const ic=(n,s)=>`<svg class="i" viewBox="0 0 24 24" aria-hidden="true"${s?` style="width:${s}px;height:${s}px"`:''}>${IC[n]||''}</svg>`;
const logo=s=>`<svg width="${s}" height="${s}" viewBox="0 0 34 34" aria-hidden="true"><circle cx="17" cy="17" r="17" fill="#174B35"/><circle cx="17" cy="17" r="9" fill="none" stroke="#CBAA62" stroke-width="2.6" stroke-linecap="round" stroke-dasharray="42 14.6" transform="rotate(-90 17 17)"/><circle cx="8" cy="17" r="2.4" fill="#16A765"/><circle cx="17" cy="17" r="2.6" fill="#F5F3EC"/></svg>`;
const LOGO=logo(34);

/* ---------- charts ---------- */
const PAL=['#16A765','#CBAA62','#6FC3A0','#B9C2CA','#3D7F63','#8E9B91','#E5A33B','#9C8A55'];
function donut(items,center){
  const tot=sum(items,i=>i.value)||1,r=52,c=2*Math.PI*r;let off=0;
  const segs=items.filter(i=>i.value>0).map(i=>{const len=i.value/tot*c;const s=`<circle cx="70" cy="70" r="${r}" fill="none" stroke="${i.color}" stroke-width="16" stroke-dasharray="${len.toFixed(2)} ${(c-len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 70 70)"/>`;off+=len;return s}).join('');
  return `<svg class="chart" viewBox="0 0 140 140" style="width:150px;height:150px;flex:none" role="img" aria-label="${esc(center.top)} breakdown chart"><circle cx="70" cy="70" r="52" fill="none" stroke="#202923" stroke-width="16"/>${segs}<text x="70" y="65" text-anchor="middle">${esc(center.top)}</text><text x="70" y="82" text-anchor="middle" class="tv" style="font:600 14px var(--serif)">${esc(center.main)}</text></svg>`;
}
function bars(data,label){
  const w=320,h=170,pl=34,pr=6,pt=18,pb=24;const max=Math.max(...data.map(d=>d.value),1);const bw=(w-pl-pr)/data.length;
  let g='';[0,.5,1].forEach(f=>{const y=pt+(h-pt-pb)*(1-f);g+=`<line x1="${pl}" x2="${w-pr}" y1="${y}" y2="${y}" stroke="rgba(245,243,236,.08)"/><text x="${pl-5}" y="${y+3}" text-anchor="end">${cmp(max*f)}</text>`});
  const b=data.map((d,i)=>{const bh=(h-pt-pb)*d.value/max;const x=pl+i*bw+bw*.2,y=h-pb-bh;
    return `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${(bw*.6).toFixed(1)}" height="${Math.max(bh,d.value>0?2:0).toFixed(1)}" rx="3" fill="${d.cur?'#CBAA62':'#16A765'}"/>${d.value>0?`<text x="${(x+bw*.3).toFixed(1)}" y="${(y-4).toFixed(1)}" text-anchor="middle" class="tv">${cmp(d.value)}</text>`:''}<text x="${(x+bw*.3).toFixed(1)}" y="${h-8}" text-anchor="middle">${esc(d.label)}</text>`}).join('');
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}">${g}${b}</svg>`;
}
function line(pts,color,label){
  if(pts.length<2)return '<div class="empty">Add at least two rates to see a trend.</div>';
  const w=320,h=150,pl=40,pr=10,pt=14,pb=22;const vs=pts.map(p=>p.v);let mn=Math.min(...vs),mx=Math.max(...vs);const m=(mx-mn)*.15||mx*.05;mn-=m;mx+=m;
  const X=i=>pl+(w-pl-pr)*i/(pts.length-1),Y=v=>pt+(h-pt-pb)*(1-(v-mn)/(mx-mn));
  const path=pts.map((p,i)=>(i?'L':'M')+X(i).toFixed(1)+' '+Y(p.v).toFixed(1)).join(' ');
  let g='';[0,.5,1].forEach(f=>{const v=mn+(mx-mn)*f,y=Y(v);g+=`<line x1="${pl}" x2="${w-pr}" y1="${y}" y2="${y}" stroke="rgba(245,243,236,.08)"/><text x="${pl-5}" y="${y+3}" text-anchor="end">${cmp(v)}</text>`});
  const last=pts[pts.length-1];
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="${esc(label)}">${g}<path d="${path} L${X(pts.length-1)} ${h-pb} L${X(0)} ${h-pb}Z" style="fill:${color};opacity:.12"/><path d="${path}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round"/><circle cx="${X(pts.length-1)}" cy="${Y(last.v)}" r="3.5" fill="${color}"/><text x="${pl}" y="${h-6}">${esc(pts[0].l)}</text><text x="${w-pr}" y="${h-6}" text-anchor="end">${esc(last.l)}</text></svg>`;
}

/* ---------- ui infra ---------- */
let lastFocus=null;
function openModal(html,layer){const root=$(layer===2?'#modal2':'#modalRoot');if(layer!==2)lastFocus=document.activeElement;
  root.innerHTML=`<div class="bd" data-a="bd"><div class="sheet" role="dialog" aria-modal="true">${html}</div></div>`;
  const f=$('input:not([type=hidden]),select,textarea',root)||$('button.btn',root);if(f)setTimeout(()=>f.focus({preventScroll:true}),30)}
function closeModal(layer){if(layer===2)releaseViewer();$(layer===2?'#modal2':'#modalRoot').innerHTML='';if(layer!==2&&lastFocus&&lastFocus.focus)try{lastFocus.focus()}catch(e){}}
function toast(msg){const t=document.createElement('div');t.className='toast';t.textContent=msg;$('#toastRoot').appendChild(t);setTimeout(()=>t.remove(),3000)}
function confirmBox(o){
  openModal(`<div class="mh"><h2>${esc(o.title)}</h2></div><p class="muted">${o.text}</p>${o.typed?`<div class="fld" style="margin-top:12px"><label for="ctyped">Type <b>${esc(o.typed)}</b> to continue</label><input id="ctyped" autocomplete="off"></div>`:''}
  <div class="mf"><button class="btn sec" data-a="close2">Cancel</button><button class="btn ${o.danger?'danger':''}" id="cyes" ${o.typed?'disabled':''}>${esc(o.yes||'Confirm')}</button></div>`,2);
  if(o.typed)$('#ctyped').addEventListener('input',e=>{$('#cyes').disabled=e.target.value.trim()!==o.typed});
  $('#cyes').addEventListener('click',()=>{closeModal(2);o.onYes()});
}
function chkFile(file,f){
  const name=file.name;const exts=(f.accept||'.pdf,.jpg,.jpeg,.png').split(',');
  if(/[\\/\u0000-\u001f]/.test(name)||name.includes('..'))return 'File name contains characters that are not allowed.';
  const ext='.'+name.split('.').pop().toLowerCase();
  if(!exts.includes(ext))return `Only ${exts.map(e=>e.slice(1).toUpperCase()).join(', ')} files are allowed.`;
  if(file.size>(f.maxMB||10)*1048576)return `File is larger than ${(f.maxMB||10)} MB.`;
  if(file.size===0)return 'File is empty.';
  return null}
function formHTML(fields,vals){return fields.map(f=>{
  const v=vals[f.k]!=null&&vals[f.k]!==''?vals[f.k]:(f.def!=null?f.def:'');const id='f_'+f.k;
  const lab=`<label for="${id}">${esc(f.label)}${f.req?' <span class="rq" aria-hidden="true">*</span>':''}</label>`;let inp;
  if(f.t==='select')inp=`<select id="${id}">${f.opts.map(o=>{const a=Array.isArray(o)?o:[o,o];return `<option value="${esc(a[0])}"${String(a[0])===String(v)?' selected':''}>${esc(a[1])}</option>`}).join('')}</select>`;
  else if(f.t==='textarea')inp=`<textarea id="${id}" rows="2" maxlength="${f.maxlen||300}">${esc(v)}</textarea>`;
  else if(f.t==='file')inp=`<input id="${id}" type="file" accept="${f.accept||'.pdf,.jpg,.jpeg,.png'}">${v?`<div class="hint">Current file: ${esc(v)}</div>`:''}`;
  else inp=`<input id="${id}" type="${f.t||'text'}" value="${esc(v)}" ${f.t==='number'?`step="${f.step||'any'}" inputmode="decimal"`:''} ${f.ph?`placeholder="${esc(f.ph)}"`:''} ${f.maxlen?`maxlength="${f.maxlen}"`:''} autocomplete="off">`;
  return `<div class="fld ${f.w==='half'?'half':''}" data-k="${f.k}"${f.showIf?` data-sk="${f.showIf[0]}" data-sv="${f.showIf[1]}"`:''}>${lab}${inp}${f.hint?`<div class="hint">${f.hint}</div>`:''}${f.calc?`<button type="button" class="link" data-a="calc">Calculate: weight × rate + making + GST</button>`:''}<div class="err" id="e_${f.k}" role="alert"></div></div>`}).join('')}
function collect(fields){const o={},errs={};
  for(const f of fields){
    if(f.showIf&&$('#f_'+f.showIf[0]).value!==f.showIf[1]){o[f.k]='';continue}
    const el=$('#f_'+f.k);let v;
    if(f.t==='file'){const file=el.files[0];v=file?file.name:(f.cur||'');if(file){const m=chkFile(file,f);if(m)errs[f.k]=m;else{o['_size_'+f.k]=file.size;o['_file_'+f.k]=file}}
      if(f.req&&!v)errs[f.k]='Choose a file.';o[f.k]=v;continue}
    v=el.value.trim();
    if(f.req&&!v){errs[f.k]=f.label+' is required.';continue}
    if(f.t==='number'&&v!==''){const n=Number(v);if(!isFinite(n)){errs[f.k]='Enter a valid number.';continue}
      if(f.min!=null&&n<f.min){errs[f.k]=`Must be ${f.min===0?'zero or more':'at least '+f.min}.`;continue}
      if(f.max!=null&&n>f.max){errs[f.k]=`Must be ${f.max} or less.`;continue}v=n}
    if(f.t==='date'&&v&&(isNaN(pd(v))||!/^\d{4}-\d{2}-\d{2}$/.test(v))){errs[f.k]='Enter a valid date.';continue}
    o[f.k]=v}
  for(const f of fields)if(f.check&&!errs[f.k]){const m=f.check(o);if(m)errs[f.k]=m}
  return{o,errs}}
function openForm(o){
  openModal(`<form id="mform" novalidate><div class="mh"><h2>${esc(o.title)}</h2><button type="button" class="icon-btn" data-a="close" aria-label="Close">${ic('x')}</button></div>${o.intro?`<p class="muted small" style="margin:-6px 0 12px">${o.intro}</p>`:''}<div class="fgrid">${formHTML(o.fields,o.vals||{})}</div><div class="mf"><button type="button" class="btn sec" data-a="close">Cancel</button><button class="btn" type="submit">${esc(o.label||'Save')}</button></div></form>`);
  const form=$('#mform');const sync=()=>$$('.fld[data-sk]',form).forEach(el=>{el.hidden=$('#f_'+el.dataset.sk).value!==el.dataset.sv});
  form.addEventListener('change',sync);sync();
  form.addEventListener('submit',async e=>{e.preventDefault();const btn=$('button[type=submit]',form);if(btn.disabled)return;const{o:vals,errs}=collect(o.fields);
    $$('.fld',form).forEach(el=>{el.classList.remove('bad');$('.err',el).textContent=''});
    const showErr=(k,m)=>{const el=$('.fld[data-k="'+k+'"]',form);if(el){el.classList.add('bad');$('.err',el).textContent=m}};
    const ks=Object.keys(errs);
    if(ks.length){ks.forEach(k=>showErr(k,errs[k]));const first=$('#f_'+ks[0]);if(first)first.focus();return}
    btn.disabled=true;const added=[],replaced=[];
    try{for(const f of o.fields){if(f.t!=='file')continue;const file=vals['_file_'+f.k];delete vals['_file_'+f.k];
        if(!file){vals[f.k+'_id']=f.curId||'';continue}
        const bytes=new Uint8Array(await file.arrayBuffer());const chk=validateUpload(file.name,bytes,f.kinds);
        if(!chk.ok){showErr(f.k,chk.error);throw 0}
        const id=await vault.putFile(bytes);added.push(id);vals[f.k]=chk.name;vals[f.k+'_id']=id;vals['_size_'+f.k]=bytes.length;if(f.curId)replaced.push(f.curId)}}
    catch(e){for(const id of added)await vault.deleteFile(id).catch(()=>{});btn.disabled=false;if(e!==0)toast('Could not store the file.');return}
    closeModal();o.save(vals);for(const id of replaced)vault.deleteFile(id).catch(()=>{})});
}

/* ---------- shared helpers ---------- */
const UI={bills:{f:'all',cat:'all',q:'',tab:'list',mode:'month',month:TODAY.slice(0,7),year:TODAY.slice(0,4)},ins:{t:'all',p:'all'},inv:{c:'all',q:''},
  gold:{tab:'assets',k:'all'},silver:{tab:'assets',k:'all'},docs:{c:'all',q:'',p:'all'},rem:{tab:'upcoming'}};
const CATS=['Housing & EMI','Utilities','Groceries','Transport','Education','Subscriptions','Health','Entertainment','Other'];
const REC=[['none','One-time'],['daily','Daily'],['weekly','Weekly'],['monthly','Monthly'],['quarterly','Quarterly'],['annual','Annually'],['custom','Custom (every N days)']];
const recName=(r,c)=>r==='custom'?`Every ${c} days`:(REC.find(x=>x[0]===r)||[0,'One-time'])[1];
const catColor=c=>PAL[Math.max(0,CATS.indexOf(c))%PAL.length];
const FAMILY=['Self','Spouse','Father','Mother','Child','Other family'];
const LOAN_KINDS=['Home','Car','Personal','Education','Other'];
const INS_TYPES=['Health','Term','Vehicle','Home','Other'];
const FREQ=[['monthly','Monthly'],['quarterly','Quarterly'],['half','Half-yearly'],['annual','Annual'],['single','Single premium']];
const FREQ_PER_YEAR={monthly:12,quarterly:4,half:2,annual:1,single:0};
const INV_CATS=['Mutual fund','Stock','ETF','REIT','Other'];
const DOC_CATS=['Identity','Passport & visa','Insurance','Financial','Property','Investment','Tax','Other personal'];
const pill=(c,t)=>`<span class="pill ${c}">${t}</span>`;
const dueInfo=d=>{const n=diff(d,TODAY);if(n<0)return pill('err','! '+(-n)+'d overdue');if(n===0)return pill('warn','◷ Due today');if(n<=7)return pill('warn','◷ In '+n+'d');return pill('',' ◷ In '+n+'d')};
const expInfo=(d,w)=>{if(!d)return pill('','No expiry');const n=diff(d,TODAY);if(n<0)return pill('err','! Expired '+(-n)+'d ago');if(n<=w)return pill('warn','◷ '+(n===0?'Today':'In '+n+'d'));return pill('ok','✓ '+fds(d)+' '+d.slice(0,4))};
const emptyBox=(t,s)=>`<div class="empty"><b>${esc(t)}</b>${esc(s||'')}</div>`;
const gainPill=(g,p)=>g===0?pill('','0.0%'):pill(g>0?'ok':'err',(g>0?'▲ ':'▼ ')+pc(p).replace(/^[+−]/,''));
const demoNote=()=>'';
function pageHead(title,sub,acts){return `<div class="ph"><div><h1>${esc(title)}</h1>${sub?`<p class="sub">${sub}</p>`:''}</div><div class="acts">${acts||''}</div></div>`}
function addBtn(act,label,cls){return `<button class="btn ${cls||''}" data-a="${act}">${ic('plus')}${esc(label)}</button>`}
const GROUPS={finance:[['bills','Bills'],['loans','Loans'],['insurance','Insurance'],['yearplan','Year plan'],['reminders','Reminders']],assets:[['invest','Investments'],['gold','Gold'],['silver','Silver'],['metals','Metals']]};
const groupOf=r=>r==='bills'||r==='loans'||r==='yearplan'||r==='insurance'||r==='reminders'?'finance':['invest','gold','silver','metals'].includes(r)?'assets':r==='docs'?'docs':r==='home'?'home':'more';
const subtabs=r=>{const g=GROUPS[groupOf(r)];return g?`<div class="tabs sub" role="tablist">${g.map(([k,l])=>`<button class="tab" role="tab" ${k===r?'aria-current="page"':''} data-a="go" data-r="${k}">${l}</button>`).join('')}</div>`:''};

/* ---------- calculations ---------- */
function commits(){const mk=TODAY.slice(0,7);const F={daily:30,weekly:52/12,monthly:1,quarterly:1/3,annual:1/12};let bills=0;
  S.bills.forEach(b=>{if(b.recurrence==='none'){if(b.dueDate.slice(0,7)===mk)bills+=b.amount}else if(b.recurrence==='custom')bills+=b.amount*30/(b.customDays||30);else bills+=b.amount*F[b.recurrence]});
  const IF={monthly:1,quarterly:1/3,half:1/6,annual:1/12,single:0};
  const ins=sum(S.ins,p=>p.premium*(IF[p.freq]||0));const sip=sum(S.inv,i=>+i.sip||0);return{bills,ins,sip,total:bills+ins+sip}}
const paidIn=pre=>{let t=0;S.bills.forEach(b=>b.history.forEach(h=>{if(h.date.startsWith(pre))t+=h.amount}));return t};
const unpaid=()=>S.bills.filter(b=>b.status!=='paid').sort((a,b)=>a.dueDate.localeCompare(b.dueDate));
const pendingThisMonth=()=>sum(unpaid().filter(b=>b.dueDate.slice(0,7)<=TODAY.slice(0,7)),b=>b.amount);
const invStats=()=>({inv:sum(S.inv,i=>i.invested),sip:sum(S.inv,i=>+i.sip||0),n:S.inv.length,nsip:S.inv.filter(i=>i.sip>0).length});
const METAL={
  gold:{key:'gold',name:'Gold',sym:'Au',cls:'gold',col:'#CBAA62',purities:['24K','22K','18K','14K'],pv:p=>parseInt(p)/24,base:'24K',kinds:['Jewellery','Coin','Bar','Other']},
  silver:{key:'silver',name:'Silver',sym:'Ag',cls:'silver',col:'#B9C2CA',purities:['999','925','800'],pv:p=>parseInt(p)/999,base:'999',kinds:['Jewellery','Coin','Bar','Utensils','Other']}};
function mStats(k){const items=S[k];return{w:sum(items,i=>i.weight),inv:sum(items,i=>i.amount),n:items.length}}
function autoReminders(){const out=[];
  unpaid().forEach(b=>out.push({src:'Bill',text:`${b.name} · ${money(b.amount)}`,due:b.dueDate,fire:addD(b.dueDate,-S.settings.adv),on:S.settings.nBills}));
  S.ins.forEach(p=>out.push({src:'Insurance',text:`${p.name} renewal`,due:p.renewal,fire:addD(p.renewal,-30),on:S.settings.nIns}));
  S.docs.filter(d=>d.expiry&&d.remind>0).forEach(d=>out.push({src:'Document',text:`${d.name} expires`,due:d.expiry,fire:addD(d.expiry,-d.remind),on:S.settings.nDocs}));
  S.inv.filter(i=>i.sip>0&&i.sipDay).forEach(i=>{let d=new Date(T0.getFullYear(),T0.getMonth(),Math.min(i.sipDay,28));if(iso(d)<TODAY)d=new Date(T0.getFullYear(),T0.getMonth()+1,Math.min(i.sipDay,28));const due=iso(d);out.push({src:'SIP',text:`${i.name} · ${money(i.sip)}`,due,fire:addD(due,-1),on:S.settings.nSip})});
  return out.filter(x=>x.on).sort((a,b)=>a.fire.localeCompare(b.fire))}

/* ---------- pages ---------- */
const PAGES={};

PAGES.home=()=>{
  const c=commits(),h=T0.getHours(),greet=h<12?'Good morning':h<17?'Good afternoon':'Good evening';
  const dateStr=T0.toLocaleDateString('en-IN',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
  const up=unpaid(),od=up.filter(b=>b.dueDate<TODAY);const st=invStats(),g=mStats('gold'),s=mStats('silver');
  const rens=S.ins.filter(p=>diff(p.renewal,TODAY)<=90).sort((a,b)=>a.renewal.localeCompare(b.renewal)).slice(0,3);
  const dx=S.docs.filter(d=>d.expiry&&diff(d.expiry,TODAY)<=90).sort((a,b)=>a.expiry.localeCompare(b.expiry)).slice(0,4);
  const rem=S.rem.filter(r=>!r.done&&r.date>=TODAY).sort((a,b)=>a.date.localeCompare(b.date)).slice(0,3),missed=S.rem.filter(r=>!r.done&&r.date<TODAY).length;
  const tot=c.total||1;
  return `
  <section class="card hero">
    <div><div class="eyebrow">${esc(dateStr)}</div><h1>${greet}, ${esc(S.settings.name)}</h1>
      <p class="muted" style="margin-top:8px">${od.length?`<span class="dn">!</span> ${od.length} bill${od.length>1?'s are':' is'} overdue.`:'No overdue bills.'} ${rens.length?`${rens.length} insurance renewal${rens.length>1?'s':''} coming up.`:''}</p></div>
    <div><div class="l muted small">Monthly commitments</div><div class="big">${money(c.total)}</div>
      <div class="seg" role="img" aria-label="Commitment split"><i style="width:${c.bills/tot*100}%;background:var(--pri)"></i><i style="width:${c.ins/tot*100}%;background:var(--gold)"></i><i style="width:${c.sip/tot*100}%;background:var(--silver)"></i></div>
      <div class="leg"><span><span class="dot" style="background:var(--pri)"></span>Bills &amp; EMIs <b>${money(c.bills)}</b></span><span><span class="dot" style="background:var(--gold)"></span>Insurance <b>${money(c.ins)}</b></span><span><span class="dot" style="background:var(--silver)"></span>SIPs <b>${money(c.sip)}</b></span></div>
      <div class="mini"><div><div class="l">Paid this month</div><div class="v">${money(paidIn(TODAY.slice(0,7)))}</div></div><div><div class="l">Still to pay</div><div class="v">${money(pendingThisMonth())}</div></div><div><div class="l">Overdue</div><div class="v ${od.length?'dn':''}">${od.length?'! ':''}${od.length}</div></div></div></div>
  </section>
  <div class="qa" style="margin:14px 0" role="group" aria-label="Quick actions">
    <button data-a="addBill"><span class="ico">${ic('wallet')}</span>Expense</button>
    <button data-a="addInv"><span class="ico">${ic('trend')}</span>Investment</button>
    <button data-a="addGold"><span class="ico gold"><b>Au</b></span>Gold</button>
    <button data-a="addSilver"><span class="ico silver"><b>Ag</b></span>Silver</button>
    <button data-a="addIns"><span class="ico">${ic('shield')}</span>Insurance</button>
    <button data-a="addDoc"><span class="ico">${ic('folder')}</span>Document</button></div>
  <div class="g2">
    <section class="card"><div class="ch"><h2>Upcoming payments</h2><button class="link" data-a="go" data-r="bills">All bills ${ic('chev',14)}</button></div>
      <div class="list">${up.slice(0,5).map(b=>`<div class="row"><button class="rmain" data-a="bill" data-id="${b.id}"><span class="av g" style="background:${catColor(b.category)}22;color:${catColor(b.category)}">${esc(b.category[0])}</span><span class="rt"><span class="t1">${esc(b.name)}</span><br><span class="t2">${esc(fds(b.dueDate))} · ${esc(recName(b.recurrence,b.customDays))}</span></span><span class="ra"><span class="amt">${money(b.amount)}</span>${dueInfo(b.dueDate)}</span></button><button class="btn sm sec" data-a="pay" data-id="${b.id}" aria-label="Mark ${esc(b.name)} as paid">Paid</button></div>`).join('')||emptyBox('All caught up','No unpaid bills.')}</div></section>
    <section class="card"><div class="ch"><h2>Investments &amp; SIPs</h2><button class="link" data-a="go" data-r="invest">Open ${ic('chev',14)}</button></div>
      <div class="tiles" style="grid-template-columns:repeat(2,1fr)"><div class="tile"><div class="l">Invested</div><div class="v">${money(st.inv)}</div></div><div class="tile"><div class="l">Holdings</div><div class="v">${st.n}</div></div><div class="tile"><div class="l">Active SIPs</div><div class="v">${st.nsip}</div></div><div class="tile"><div class="l">SIPs per month</div><div class="v">${money(st.sip)}</div></div></div>
      <p class="small muted" style="margin-top:10px">Shows what you have put in. No market prices are used.</p></section>
    <section class="card span2"><div class="ch"><h2>Precious metals</h2><button class="link" data-a="go" data-r="metals">Portfolio ${ic('chev',14)}</button></div>
      <div class="tiles" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">
        <button class="tile gold" data-a="go" data-r="gold" style="text-align:left;color:inherit;cursor:pointer"><div class="l">Gold weight</div><div class="v">${wt(g.w)}</div><div class="s">${g.n?money(g.inv)+' paid':'No gold recorded'}</div></button>
        <button class="tile silver" data-a="go" data-r="silver" style="text-align:left;color:inherit;cursor:pointer"><div class="l">Silver weight</div><div class="v">${wt(s.w)}</div><div class="s">${s.n?money(s.inv)+' paid':'No silver recorded'}</div></button>
        <div class="tile"><div class="l">Total paid for metals</div><div class="v">${money(g.inv+s.inv)}</div><div class="s">Weights are kept separate</div></div></div></section>
    <section class="card"><div class="ch"><h2>Loans</h2><button class="link" data-a="go" data-r="loans">Loans ${ic('chev',14)}</button></div>
      <div class="list">${S.loans.map(l=>`<div class="row"><button class="rmain" data-a="loan" data-id="${l.id}"><span class="av g">${esc(l.kind[0])}</span><span class="rt"><span class="t1">${esc(l.name)}</span><br><span class="t2">${leftTxt(l.end)} · EMI ${money(l.emi)}</span></span><span class="ra"><span class="amt">${money(l.outstanding)}</span><span class="t2">outstanding</span></span></button></div>`).join('')||emptyBox('No loans recorded')}</div></section>
    <section class="card"><div class="ch"><h2>Insurance renewals</h2><button class="link" data-a="go" data-r="insurance">Policies ${ic('chev',14)}</button></div>
      <div class="list">${rens.map(p=>`<div class="row"><button class="rmain" data-a="ins" data-id="${p.id}"><span class="av g">${ic('shield',18)}</span><span class="rt"><span class="t1">${esc(p.name)}</span><br><span class="t2">${esc(p.provider)} · ${money(p.premium)}</span></span><span class="ra">${expInfo(p.renewal,45)}</span></button></div>`).join('')||emptyBox('Nothing due soon','No renewals in the next 90 days.')}</div></section>
    <section class="card"><div class="ch"><h2>Document alerts</h2><button class="link" data-a="go" data-r="docs">Documents ${ic('chev',14)}</button></div>
      <div class="list">${dx.map(d=>`<div class="row"><button class="rmain" data-a="doc" data-id="${d.id}"><span class="av g">${ic('file',18)}</span><span class="rt"><span class="t1">${esc(d.name)}</span><br><span class="t2">${esc(d.category)}</span></span><span class="ra">${expInfo(d.expiry,60)}</span></button></div>`).join('')||emptyBox('No expiries soon','Nothing expires in the next 90 days.')}</div></section>
    <section class="card"><div class="ch"><h2>Reminders</h2><button class="link" data-a="go" data-r="reminders">Manage ${ic('chev',14)}</button></div>
      <div class="list">${rem.map(r=>`<div class="row"><button class="rmain" data-a="remEdit" data-id="${r.id}"><span class="av g">${ic('bell',18)}</span><span class="rt"><span class="t1">${esc(r.title)}</span><br><span class="t2">${esc(fds(r.date))} · ${esc(r.time)} · ${esc(recName(r.recurrence,r.custom))}</span></span></button></div>`).join('')||emptyBox('No upcoming reminders')}</div>
      ${missed?`<div class="note warn" style="margin-top:8px">${ic('alert')}<div>${missed} missed reminder${missed>1?'s':''}. <button class="link" data-a="remTab" data-t="missed" style="padding:0">Review</button></div></div>`:''}</section>
    <section class="card"><div class="ch"><h2>Recent activity</h2></div>
      <div class="list">${S.activity.slice(0,6).map(a=>`<div class="row"><div class="rmain" style="cursor:default"><span class="av g">${ic(a.type==='pay'?'check':a.type==='doc'?'file':a.type==='del'?'trash':'edit',17)}</span><span class="rt"><span class="t1" style="font-weight:500">${esc(a.text)}</span><br><span class="t2">${ago(a.ts)}</span></span></div></div>`).join('')||emptyBox('No activity yet')}</div></section>
  </div>${demoNote()}`};

/* ----- Bills ----- */
function billList(){const u=UI.bills;const q=u.q.toLowerCase();
  let a=S.bills.filter(b=>(u.cat==='all'||b.category===u.cat)&&(!q||(b.name+b.category+b.notes).toLowerCase().includes(q)));
  if(u.f==='unpaid')a=a.filter(b=>b.status!=='paid');if(u.f==='overdue')a=a.filter(b=>b.status!=='paid'&&b.dueDate<TODAY);
  if(u.f==='paid')a=a.filter(b=>b.status==='paid'||b.history.some(h=>h.date.startsWith(TODAY.slice(0,7))));if(u.f==='recurring')a=a.filter(b=>b.recurrence!=='none');
  a.sort((x,y)=>(x.status==='paid')-(y.status==='paid')||x.dueDate.localeCompare(y.dueDate));
  if(!a.length)return emptyBox(S.bills.length?'No bills match':'No bills yet',S.bills.length?'Try a different filter or search.':'Tap “Add bill” to record your first one.');
  return `<div class="list">${a.map(b=>{const paid=b.status==='paid';return `<div class="row"><button class="rmain" data-a="bill" data-id="${b.id}"><span class="av g" style="background:${catColor(b.category)}22;color:${catColor(b.category)}">${esc(b.category[0])}</span><span class="rt"><span class="t1">${esc(b.name)}</span><br><span class="t2">${esc(b.category)} · ${esc(recName(b.recurrence,b.customDays))}${b.attach?' · Attachment':''}</span></span><span class="ra"><span class="amt">${money(b.amount)}</span>${paid?pill('ok','✓ Paid '+fds(b.paidDate)):dueInfo(b.dueDate)}</span></button>${paid?'':`<button class="btn sm sec" data-a="pay" data-id="${b.id}" aria-label="Mark ${esc(b.name)} as paid">Mark paid</button>`}</div>`}).join('')}</div>`}
function billSummary(){const u=UI.bills;const pre=u.mode==='month'?u.month:u.year;
  const years=[...new Set([TODAY.slice(0,4),...S.bills.flatMap(b=>b.history.map(h=>h.date.slice(0,4)))])].sort().reverse();
  const months=[];for(let i=0;i<12;i++)months.push(addM(TODAY.slice(0,8)+'01',-i).slice(0,7));
  const byCat={};let total=0,count=0;S.bills.forEach(b=>b.history.forEach(h=>{if(h.date.startsWith(pre)){byCat[b.category]=(byCat[b.category]||0)+h.amount;total+=h.amount;count++}}));
  const items=Object.entries(byCat).sort((a,b)=>b[1]-a[1]).map(([k,v])=>({label:k,value:v,color:catColor(k)}));
  let series=[];if(u.mode==='month'){const base=u.month+'-01';for(let i=5;i>=0;i--){const k=addM(base,-i).slice(0,7);series.push({label:monthShort(k),value:paidIn(k),cur:k===u.month})}}
  else for(let m=1;m<=12;m++){const k=u.year+'-'+pad(m);series.push({label:monthShort(k),value:paidIn(k),cur:k===TODAY.slice(0,7)})}
  return `<div class="toolbar"><div class="chips" role="group" aria-label="Period"><button class="chip" aria-pressed="${u.mode==='month'}" data-a="bMode" data-m="month">Monthly</button><button class="chip" aria-pressed="${u.mode==='year'}" data-a="bMode" data-m="year">Yearly</button></div>
    <div style="min-width:160px">${u.mode==='month'?`<select id="sumPeriod" data-sel="bMonth" aria-label="Month">${months.map(m=>`<option value="${m}"${m===u.month?' selected':''}>${monthLabel(m)}</option>`).join('')}</select>`:`<select id="sumPeriod" data-sel="bYear" aria-label="Year">${years.map(y=>`<option${y===u.year?' selected':''}>${y}</option>`).join('')}</select>`}</div></div>
  <div class="tiles" style="margin:8px 0 14px"><div class="tile"><div class="l">Paid ${u.mode==='month'?monthLabel(u.month):u.year}</div><div class="v">${money(total)}</div></div><div class="tile"><div class="l">Payments</div><div class="v">${count}</div></div><div class="tile"><div class="l">Average per payment</div><div class="v">${money(count?total/count:0)}</div></div></div>
  <div class="g2"><section class="card"><h2>${u.mode==='month'?'Last 6 months':'Month by month'}</h2><div style="margin-top:8px">${bars(series,'Amount paid per month')}</div></section>
  <section class="card"><h2>By category</h2>${items.length?`<div class="donutwrap" style="margin-top:10px">${donut(items,{top:'Total',main:cmp(total)})}<div class="leg">${items.map(i=>`<div><span><span class="dot" style="background:${i.color}"></span>${esc(i.label)}</span><b>${money(i.value)} · ${Math.round(i.value/total*100)}%</b></div>`).join('')}</div></div>`:emptyBox('No payments in this period')}</section></div>`}
PAGES.bills=()=>{const u=UI.bills;const up=unpaid(),od=up.filter(b=>b.dueDate<TODAY);
  return `${subtabs('bills')}${pageHead('Bills & Expenses','Track what is due, what is paid and where the money goes.',addBtn('addBill','Add bill'))}
  <div class="tabs" role="tablist"><button class="tab" role="tab" aria-selected="${u.tab==='list'}" data-a="bTab" data-t="list">Bills</button><button class="tab" role="tab" aria-selected="${u.tab==='sum'}" data-a="bTab" data-t="sum">Summary</button></div>
  ${u.tab==='sum'?billSummary():`<div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Paid this month</div><div class="v">${money(paidIn(TODAY.slice(0,7)))}</div></div><div class="tile"><div class="l">Still to pay</div><div class="v">${money(pendingThisMonth())}</div></div><div class="tile"><div class="l">Overdue</div><div class="v ${od.length?'dn':''}">${od.length?'! ':''}${od.length}</div><div class="s">${od.length?money(sum(od,b=>b.amount)):'None'}</div></div></div>
  <div class="toolbar"><div class="search">${ic('search')}<input id="q" type="search" placeholder="Search bills" value="${esc(u.q)}" aria-label="Search bills" data-q="bills"></div><div style="min-width:170px"><select data-sel="bCat" aria-label="Category"><option value="all">All categories</option>${CATS.map(c=>`<option${c===u.cat?' selected':''}>${c}</option>`).join('')}</select></div></div>
  <div class="chips" role="group" aria-label="Filter">${[['all','All'],['unpaid','Unpaid'],['overdue','Overdue'],['paid','Paid'],['recurring','Recurring']].map(([k,l])=>`<button class="chip" aria-pressed="${u.f===k}" data-a="bFilter" data-f="${k}">${l}</button>`).join('')}</div>
  <section class="card" id="list">${billList()}</section>`}`};

/* ----- Insurance ----- */
PAGES.insurance=()=>{const t=UI.ins.t,pp=UI.ins.p;const a=S.ins.filter(p=>(t==='all'||p.type===t)&&(pp==='all'||(p.owner||'Self')===pp)).sort((x,y)=>x.renewal.localeCompare(y.renewal));
  const annual=sum(S.ins,p=>p.premium*(FREQ_PER_YEAR[p.freq]||0)),next=[...S.ins].sort((x,y)=>x.renewal.localeCompare(y.renewal))[0];
  return `${subtabs('insurance')}${pageHead('Insurance Manager','Policies, premiums and renewal dates in one place.',addBtn('addIns','Add policy'))}
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Policies</div><div class="v">${S.ins.length}</div></div><div class="tile"><div class="l">Total cover</div><div class="v">${money(sum(S.ins,p=>p.coverage))}</div></div><div class="tile"><div class="l">Premiums per year</div><div class="v">${money(annual)}</div></div><div class="tile"><div class="l">Next renewal</div><div class="v" style="font-size:18px">${next?fds(next.renewal):'—'}</div><div class="s">${next?esc(next.name):''}</div></div></div>
  <div class="toolbar"><div style="min-width:180px"><select data-sel="iOwn" aria-label="Person"><option value="all">Everyone</option>${FAMILY.map(f=>`<option${f===UI.ins.p?' selected':''}>${f}</option>`).join('')}</select></div></div>
  <div class="chips" role="group" aria-label="Policy type">${['all',...INS_TYPES].map(k=>`<button class="chip" aria-pressed="${t===k}" data-a="iType" data-t="${k}">${k==='all'?'All':k}</button>`).join('')}</div>
  <div class="g2">${a.map(p=>`<button class="card" data-a="ins" data-id="${p.id}" style="text-align:left;color:inherit;display:block;width:100%"><div style="display:flex;gap:12px;align-items:flex-start;justify-content:space-between"><div style="min-width:0"><div class="eyebrow">${esc(p.type)} insurance · ${esc(p.owner||'Self')}</div><h2 style="margin-top:4px;overflow-wrap:anywhere">${esc(p.name)}</h2><div class="t2">${esc(p.provider)}</div></div>${expInfo(p.renewal,45)}</div>
    <div class="kv" style="margin-top:14px"><div><div class="l">Cover</div><div class="v amt">${money(p.coverage)}</div></div><div><div class="l">Premium</div><div class="v amt">${money(p.premium)} <span class="muted small" style="font:500 12px var(--sans)">${esc((FREQ.find(f=>f[0]===p.freq)||[0,''])[1].toLowerCase())}</span></div></div><div><div class="l">Policy no.</div><div class="v num">•••• ${esc(p.number.slice(-4))}</div></div><div><div class="l">Renews</div><div class="v">${fd(p.renewal)}</div></div></div></button>`).join('')||`<div class="span2">${emptyBox('No policies','Add a policy to track its renewal.')}</div>`}</div>`};

/* ----- Investments ----- */
function invList(){const u=UI.inv,q=u.q.toLowerCase();let a=S.inv.filter(i=>(u.c==='all'||(u.c==='sip'?i.sip>0:i.category===u.c))&&(!q||(i.name+i.platform).toLowerCase().includes(q)));
  if(!a.length)return emptyBox(S.inv.length?'No investments match':'No investments yet',S.inv.length?'Try a different filter.':'Add a fund, stock or SIP to begin.');
  return `<div class="list">${a.map(i=>{
    return `<div class="row"><button class="rmain" data-a="inv" data-id="${i.id}"><span class="av g">${esc(i.category.split(' ').map(w=>w[0]).join('').slice(0,2))}</span><span class="rt"><span class="t1">${esc(i.name)}</span><br><span class="t2">${esc(i.category)} · ${esc(i.platform||'—')}${i.sip>0?' · SIP '+money(i.sip):''}</span></span><span class="ra"><span class="amt">${money(i.invested)}</span><span class="t2">${i.units?i.units.toLocaleString('en-IN',{maximumFractionDigits:3})+' units':'Invested'}</span></span></button></div>`}).join('')}</div>`}
PAGES.invest=()=>{const u=UI.inv,st=invStats();
  const byCat=INV_CATS.map((c,i)=>({label:c,value:sum(S.inv.filter(x=>x.category===c),x=>x.invested),color:PAL[i]})).filter(x=>x.value>0);
  return `${subtabs('invest')}${pageHead('Investments & SIPs','Funds, stocks, ETFs and REITs, and what you have put into each.',addBtn('addInv','Add investment'))}
  <div class="note" style="margin-bottom:14px">${ic('info')}<div>This tracker records what you have invested and your monthly SIPs. It does not track market prices, gains or losses.</div></div>
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Total invested</div><div class="v">${money(st.inv)}</div></div><div class="tile"><div class="l">SIPs per month</div><div class="v">${money(st.sip)}</div></div><div class="tile"><div class="l">SIPs per year</div><div class="v">${money(st.sip*12)}</div></div><div class="tile"><div class="l">Holdings</div><div class="v">${st.n}</div></div></div>
  <div class="g2"><section class="card"><h2>By category</h2>${byCat.length?`<div class="donutwrap" style="margin-top:10px">${donut(byCat,{top:'Total invested',main:cmp(st.inv)})}<div class="leg">${byCat.map(i=>`<div><span><span class="dot" style="background:${i.color}"></span>${esc(i.label)}</span><b>${Math.round(i.value/st.inv*100)}%</b></div>`).join('')}</div></div>`:emptyBox('Nothing to chart yet')}</section>
  <section class="card"><h2>Monthly SIPs</h2><div class="list" style="margin-top:6px">${S.inv.filter(i=>i.sip>0).map(i=>`<div class="row"><div class="rmain" style="cursor:default"><span class="rt"><span class="t1">${esc(i.name)}</span><br><span class="t2">Debits on the ${i.sipDay}${['th','st','nd','rd'][(i.sipDay%100>10&&i.sipDay%100<14)?0:Math.min(i.sipDay%10,4)%4]||'th'}</span></span><span class="amt">${money(i.sip)}</span></div></div>`).join('')||emptyBox('No SIPs set up')}</div></section></div>
  <div class="toolbar" style="margin-top:14px"><div class="search">${ic('search')}<input id="q" type="search" placeholder="Search investments" value="${esc(u.q)}" aria-label="Search investments" data-q="inv"></div></div>
  <div class="chips" role="group" aria-label="Filter">${[['all','All'],...INV_CATS.map(c=>[c,c]),['sip','SIP only']].map(([k,l])=>`<button class="chip" aria-pressed="${u.c===k}" data-a="iFilter" data-c="${k}">${l}</button>`).join('')}</div>
  <section class="card" id="list">${invList()}</section>`};

/* ----- Gold & Silver ----- */
function metalPage(k){const M=METAL[k],u=UI[k],st=mStats(k),items=S[k];
  const tabs=[['assets','Assets'],['history','Purchase history']];let body='';
  if(u.tab==='assets'){const a=items.filter(i=>u.k==='all'||i.kind===u.k).sort((x,y)=>y.date.localeCompare(x.date));
    body=`<div class="chips" role="group" aria-label="Type">${['all',...M.kinds].map(x=>`<button class="chip" aria-pressed="${u.k===x}" data-a="mKind" data-m="${k}" data-x="${x}">${x==='all'?'All':x}</button>`).join('')}</div>
    <section class="card">${a.length?`<div class="list">${a.map(i=>`<div class="row"><button class="rmain" data-a="metal" data-m="${k}" data-id="${i.id}"><span class="av ${M.cls}">${M.sym}</span><span class="rt"><span class="t1">${esc(i.name)}</span><br><span class="t2">${esc(i.kind)} · ${esc(i.purity)}</span><br><span class="t2">Bought ${fd(i.date)}${i.seller?' · '+esc(i.seller):''}</span></span><span class="ra"><span class="amt">${wt(i.weight)}</span><span class="t2">Paid ${money(i.amount)}</span></span></button></div>`).join('')}</div>`:emptyBox(`No ${M.name.toLowerCase()} recorded`,'Add an asset to start tracking.')}</section>`}
  else{let run=0;const a=[...items].sort((x,y)=>x.date.localeCompare(y.date)).map(i=>{run+=i.amount;return{...i,run}}).reverse();
    body=`<section class="card">${a.length?`<div class="list">${a.map(i=>`<div class="row"><button class="rmain" data-a="metal" data-m="${k}" data-id="${i.id}"><span class="rt"><span class="t1">${fd(i.date)} · ${esc(i.name)}</span><br><span class="t2">${wt(i.weight)} · ${esc(i.purity)} · ${esc(i.seller||'Seller not recorded')}</span></span><span class="ra"><span class="amt">${money(i.amount)}</span><span class="t2">Total so far ${money(i.run)}</span></span></button></div>`).join('')}</div>`:emptyBox('No purchases yet')}</section>`}
  return `${subtabs(k)}${pageHead(M.name+' Tracker',k==='gold'?'Jewellery, coins and bars: how much you own and what you paid.':'Jewellery, coins, bars and utensils: how much you own and what you paid.',addBtn(k==='gold'?'addGold':'addSilver','Add '+M.name.toLowerCase(),M.cls))}
  <div class="tiles" style="margin-bottom:14px"><div class="tile ${M.cls}"><div class="l">Total weight</div><div class="v">${wt(st.w)}</div></div><div class="tile"><div class="l">Total amount paid</div><div class="v">${money(st.inv)}</div><div class="s">Includes making charges and GST</div></div><div class="tile"><div class="l">Assets</div><div class="v">${st.n}</div></div></div>
  <div class="tabs" role="tablist">${tabs.map(([t,l])=>`<button class="tab" role="tab" aria-selected="${u.tab===t}" data-a="mTab" data-m="${k}" data-t="${t}">${l}</button>`).join('')}</div>${body}`}
PAGES.gold=()=>metalPage('gold');PAGES.silver=()=>metalPage('silver');
PAGES.metals=()=>{const g=mStats('gold'),s=mStats('silver');const tot=g.inv+s.inv;
  const panel=(M,st)=>`<section class="card" style="border-color:${M.col}55"><div class="ch"><h2 style="color:${M.col}">${M.name}</h2><button class="link" data-a="go" data-r="${M.key}">Open ${ic('chev',14)}</button></div>
    <div class="kv"><div><div class="l">Weight</div><div class="v amt" style="color:${M.col}">${wt(st.w)}</div></div><div><div class="l">Assets</div><div class="v amt">${st.n}</div></div><div class="full"><div class="l">Amount paid</div><div class="v amt">${money(st.inv)}</div></div></div></section>`;
  return `${subtabs('metals')}${pageHead('Precious Metals','Gold and silver side by side. Weights are never added together.')}
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Total paid for gold</div><div class="v">${money(g.inv)}</div></div><div class="tile"><div class="l">Total paid for silver</div><div class="v">${money(s.inv)}</div></div><div class="tile"><div class="l">Combined amount paid</div><div class="v">${money(tot)}</div></div></div>
  <div class="g2">${panel(METAL.gold,g)}${panel(METAL.silver,s)}</div>
  <section class="card" style="margin-top:14px"><h2>Share of amount paid</h2><div class="bar" style="margin:12px 0 8px" role="img" aria-label="Gold and silver share of amount paid"><i style="width:${tot?g.inv/tot*100:0}%;background:var(--gold)"></i><i style="width:${tot?s.inv/tot*100:0}%;background:var(--silver)"></i></div>
  <div class="leg"><span><span class="dot" style="background:var(--gold)"></span>Gold <b>${tot?Math.round(g.inv/tot*100):0}%</b></span><span><span class="dot" style="background:var(--silver)"></span>Silver <b>${tot?Math.round(s.inv/tot*100):0}%</b></span></div></section>
  <p class="small muted" style="margin-top:12px">This app records what you own and what you paid. It does not estimate today’s value.</p>`};

/* ----- Documents ----- */
function docList(){const u=UI.docs,q=u.q.toLowerCase();
  const a=S.docs.filter(d=>(u.c==='all'||d.category===u.c)&&(u.p==='all'||(d.owner||'Self')===u.p)&&(!q||(d.name+d.description+d.category).toLowerCase().includes(q))).sort((x,y)=>(x.expiry||'9999').localeCompare(y.expiry||'9999'));
  if(!a.length)return emptyBox(S.docs.length?'No documents match':'No documents yet',S.docs.length?'Try another category or search.':'Add your first document.');
  return `<div class="list">${a.map(d=>`<div class="row"><button class="rmain" data-a="doc" data-id="${d.id}"><span class="av g">${ic('file',18)}</span><span class="rt"><span class="t1">${esc(d.name)}</span><br><span class="t2">${esc(d.owner||'Self')} · ${esc(d.category)}${d.file?' · '+esc(d.file):''}</span></span><span class="ra">${d.expiry?expInfo(d.expiry,d.remind||60):pill('','No expiry')}</span></button></div>`).join('')}</div>`}
PAGES.docs=()=>{const u=UI.docs;const soon=S.docs.filter(d=>d.expiry&&diff(d.expiry,TODAY)>=0&&diff(d.expiry,TODAY)<=90).length,exp=S.docs.filter(d=>d.expiry&&diff(d.expiry,TODAY)<0).length;
  return `${pageHead('Documents','A private vault for the papers you cannot afford to lose.',addBtn('addDoc','Add document'))}
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Documents</div><div class="v">${S.docs.length}</div></div><div class="tile"><div class="l">Expiring in 90 days</div><div class="v ${soon?'':''}">${soon}</div></div><div class="tile"><div class="l">Expired</div><div class="v ${exp?'dn':''}">${exp?'! ':''}${exp}</div></div></div>
  <div class="note" style="margin-bottom:14px">${ic('lock')}<div>Attached files are encrypted on this phone with the same key as the rest of your data. They are never uploaded.</div></div>
  <div class="toolbar"><div class="search">${ic('search')}<input id="q" type="search" placeholder="Search documents" value="${esc(u.q)}" aria-label="Search documents" data-q="docs"></div><div style="min-width:170px"><select data-sel="dOwn" aria-label="Person"><option value="all">Everyone</option>${FAMILY.map(f=>`<option${f===u.p?' selected':''}>${f}</option>`).join('')}</select></div></div>
  <div class="chips" role="group" aria-label="Category">${['all',...DOC_CATS].map(c=>`<button class="chip" aria-pressed="${u.c===c}" data-a="dCat" data-c="${c}">${c==='all'?'All':c} ${c==='all'?'':`<span class="muted">${S.docs.filter(d=>d.category===c).length}</span>`}</button>`).join('')}</div>
  <section class="card" id="list">${docList()}</section>`};

/* ----- Reminders ----- */
PAGES.reminders=()=>{const u=UI.rem;const R=S.rem;const upc=R.filter(r=>!r.done&&r.date>=TODAY).sort((a,b)=>a.date.localeCompare(b.date)),mis=R.filter(r=>!r.done&&r.date<TODAY).sort((a,b)=>b.date.localeCompare(a.date)),dn=R.filter(r=>r.done);
  const auto=autoReminders();const tabs=[['upcoming','Upcoming',upc.length],['missed','Missed',mis.length],['done','Completed',dn.length],['auto','Automatic',auto.length]];
  const row=(r,kind)=>`<div class="row"><button class="btn sm sec" style="width:36px;padding:0" data-a="remDone" data-id="${r.id}" aria-label="${r.done?'Mark as not done':'Mark as done'}: ${esc(r.title)}">${r.done?ic('check',16):'○'}</button><button class="rmain" data-a="remEdit" data-id="${r.id}"><span class="rt"><span class="t1" ${r.done?'style="text-decoration:line-through;color:var(--tx2)"':''}>${esc(r.title)}</span><br><span class="t2">${fd(r.date)} · ${esc(r.time)} · ${esc(recName(r.recurrence,r.custom))}${r.advance?` · ${r.advance}d notice`:''}</span></span>${kind==='missed'?pill('err','! Missed'):kind==='done'?pill('ok','✓ Done'):dueInfo(r.date)}</button></div>`;
  let body='';
  if(u.tab==='auto')body=`<div class="note" style="margin-bottom:12px">${ic('info')}<div>These are created from your bills, policies, documents and SIPs. Each source creates one reminder per due date, so you never get duplicates. Turn types on or off in Settings.</div></div><section class="card"><div class="list">${auto.map(a=>`<div class="row"><div class="rmain" style="cursor:default"><span class="av g">${esc(a.src[0])}</span><span class="rt"><span class="t1">${esc(a.text)}</span><br><span class="t2">${esc(a.src)} · due ${fd(a.due)} · alert ${fds(a.fire)}</span></span>${a.fire<=TODAY?pill('ok','✓ Sent'):pill('','◷ Scheduled')}</div></div>`).join('')||emptyBox('Nothing scheduled')}</div></section>`;
  else{const l=u.tab==='upcoming'?upc:u.tab==='missed'?mis:dn;body=`<section class="card">${l.length?`<div class="list">${l.map(r=>row(r,u.tab)).join('')}</div>`:emptyBox(u.tab==='missed'?'Nothing missed':u.tab==='done'?'Nothing completed yet':'No upcoming reminders',u.tab==='upcoming'?'Tap “Add reminder” to create one.':'')}</section>`}
  const hide=S.settings.hideNotif;
  return `${subtabs('reminders')}${pageHead('Reminders','One place for every date that matters.',addBtn('addRem','Add reminder'))}
  <div class="tabs" role="tablist">${tabs.map(([k,l,n])=>`<button class="tab" role="tab" aria-selected="${u.tab===k}" data-a="remTab" data-t="${k}">${l} <span class="muted">${n}</span></button>`).join('')}</div>${body}
  <section class="card" style="margin-top:14px"><h2>How a notification looks</h2><div style="margin-top:10px;background:var(--surf);border-radius:14px;padding:12px 14px;display:flex;gap:12px;align-items:center;max-width:420px">${LOGO}<div style="min-width:0"><div class="t1" style="font-size:13px">My Life Manager</div><div class="t2">${hide?'A payment is due soon. Open the app to see details.':'Home loan EMI · ₹38,500 is due in 3 days'}</div></div></div><p class="small muted" style="margin-top:8px">${hide?'Details are hidden on the lock screen (recommended).':'Amounts and names are shown on the lock screen.'} <button class="link" data-a="go" data-r="prefs" style="padding:0">Change in Settings</button></p></section>`};


/* ----- Loans ----- */
const monthsLeft=e=>{const a=pd(TODAY),b=pd(e);return Math.max(0,(b.getFullYear()-a.getFullYear())*12+b.getMonth()-a.getMonth())};
const leftTxt=e=>{const m=monthsLeft(e);if(!m)return 'Final EMI due';const y=Math.floor(m/12),r=m%12;return (y?y+' yr'+(y>1?'s':'')+' ':'')+(r?r+' mo ':'')+'left'};
const repaid=l=>l.principal?Math.max(0,Math.min(100,(l.principal-l.outstanding)/l.principal*100)):0;
PAGES.loans=()=>{const L=S.loans,out=sum(L,l=>l.outstanding),emi=sum(L,l=>l.emi),far=[...L].sort((a,b)=>b.end.localeCompare(a.end))[0];
  return `${subtabs('loans')}${pageHead('Loans','Balances, EMIs and how long each loan has left.',addBtn('addLoan','Add loan'))}
  <div class="note" style="margin-bottom:14px">${ic('info')}<div>Loan EMIs are also tracked as bills, so you get due-date reminders there. This screen shows the bigger picture.</div></div>
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Loans</div><div class="v">${L.length}</div></div><div class="tile"><div class="l">Total outstanding</div><div class="v">${money(out)}</div></div><div class="tile"><div class="l">EMIs per month</div><div class="v">${money(emi)}</div></div><div class="tile"><div class="l">Last EMI</div><div class="v" style="font-size:18px">${far?fd(far.end):'—'}</div><div class="s">${far?leftTxt(far.end):''}</div></div></div>
  <section class="card">${L.length?`<div class="list">${[...L].sort((a,b)=>b.outstanding-a.outstanding).map(l=>`<div class="row"><button class="rmain" data-a="loan" data-id="${l.id}"><span class="av g">${esc(l.kind[0])}</span><span class="rt"><span class="t1">${esc(l.name)}</span><br><span class="t2">${esc(l.lender||'Lender not recorded')} · ${l.rate}% a year</span><div class="bar" style="margin-top:7px;max-width:260px" role="img" aria-label="${Math.round(repaid(l))}% repaid"><i style="width:${repaid(l)}%;background:var(--pri)"></i></div><span class="t2">${Math.round(repaid(l))}% repaid · ${leftTxt(l.end)}</span></span><span class="ra"><span class="amt">${money(l.outstanding)}</span><span class="t2">outstanding</span><span class="t2">EMI ${money(l.emi)}</span></span></button></div>`).join('')}</div>`:emptyBox('No loans recorded','Add a loan to see its balance and time left.')}</section>`};
function loanForm(l){l=l||{};
  openForm({title:l.id?'Edit loan':'Add loan',vals:l,label:l.id?'Save changes':'Add loan',fields:[
    {k:'name',label:'Loan name',req:true,maxlen:60,ph:'e.g. Home loan'},{k:'kind',label:'Type',t:'select',opts:LOAN_KINDS,w:'half'},{k:'lender',label:'Lender',maxlen:60,w:'half'},
    {k:'principal',label:'Original loan amount',t:'number',req:true,min:1,w:'half'},{k:'outstanding',label:'Outstanding balance',t:'number',req:true,min:0,w:'half',check:o=>o.outstanding>o.principal?'Cannot be more than the original amount.':null},
    {k:'rate',label:'Interest rate (% a year)',t:'number',req:true,min:0,max:60,w:'half'},{k:'emi',label:'EMI amount',t:'number',req:true,min:1,w:'half'},
    {k:'emiDay',label:'EMI date (day of month)',t:'number',req:true,min:1,max:28,w:'half'},{k:'start',label:'Loan start date',t:'date',req:true,w:'half'},
    {k:'end',label:'Final EMI date',t:'date',req:true,check:o=>o.start&&o.end<=o.start?'Final EMI must be after the start date.':null},{k:'notes',label:'Notes',t:'textarea',maxlen:200}],
    save:v=>{const n={...l,id:l.id||uid(),...v};if(l.id)S.loans[S.loans.findIndex(x=>x.id===l.id)]=n;else S.loans.push(n);log((l.id?'Edited loan ':'Added loan ')+n.name,'edit');persist();toast(l.id?'Loan updated':'Loan added');render(true)}})}
function balForm(id){const l=find('loans',id);
  openForm({title:'Update balance',intro:esc(l.name)+'. Enter the outstanding amount from your lender’s statement.',label:'Update',vals:{outstanding:l.outstanding},fields:[{k:'outstanding',label:'Outstanding balance',t:'number',req:true,min:0,check:o=>o.outstanding>l.principal?'Cannot be more than the original amount.':null}],
    save:v=>{l.outstanding=v.outstanding;log(`Updated balance of ${l.name}`,'edit');persist();toast('Balance updated');render(true);loanDetail(id)}})}
function loanDetail(id){const l=find('loans',id);if(!l)return;
  openModal(head(l.name)+`<div class="eyebrow" style="margin:-8px 0 12px">${esc(l.kind)} loan · ${esc(l.lender||'Lender not recorded')}</div><div class="bar" style="margin-bottom:6px"><i style="width:${repaid(l)}%;background:var(--pri)"></i></div><p class="t2" style="margin-bottom:14px">${Math.round(repaid(l))}% repaid · ${leftTxt(l.end)}</p><div class="kv">${kvp('Outstanding',`<span class="amt">${money(l.outstanding)}</span>`)}${kvp('Original amount',`<span class="amt">${money(l.principal)}</span>`)}${kvp('Interest rate',l.rate+'% a year')}${kvp('EMI',`<span class="amt">${money(l.emi)}</span> on day ${l.emiDay}`)}${kvp('Started',fd(l.start))}${kvp('Final EMI',fd(l.end))}${l.notes?kvp('Notes',esc(l.notes),1):''}</div>`+editDel('loans',id,`<button class="btn" data-a="updBal" data-id="${id}">Update balance</button>`))}

/* ----- Year plan ----- */
function yearPlan(){const first=TODAY.slice(0,8)+'01';const months=[];for(let i=0;i<12;i++)months.push(addM(first,i).slice(0,7));
  const idx={};months.forEach((m,i)=>idx[m]=i);const rows=months.map(m=>({m,bills:0,ins:0,sip:0,items:[]}));const end=addM(first,12);
  const add=(date,amt,key,name)=>{const k=date.slice(0,7);if(k in idx){rows[idx[k]][key]+=amt;rows[idx[k]].items.push({n:name,a:amt,k:key})}};
  S.bills.forEach(b=>{if(b.recurrence==='none'){if(b.status!=='paid')add(b.dueDate<first?first:b.dueDate,b.amount,'bills',b.name);return}
    let d=b.dueDate,n=0;if(d<first)add(first,b.amount,'bills',b.name);
    while(d<first&&n<4000){d=stepRec(d,b.recurrence,b.customDays,1);n++}
    while(d<end&&n<4000){add(d,b.amount,'bills',b.name);d=stepRec(d,b.recurrence,b.customDays,1);n++}});
  const STEP={monthly:1,quarterly:3,half:6,annual:12};
  S.ins.forEach(p=>{const st=STEP[p.freq];if(!st)return;let d=p.renewal,n=0;while(d<first&&n<200){d=addM(d,st);n++}while(d<end&&n<200){add(d,p.premium,'ins',p.name+' premium');d=addM(d,st);n++}});
  months.forEach((m,i)=>S.inv.forEach(v=>{if(v.sip>0)add(m+'-01',v.sip,'sip',v.name+' SIP')}));
  rows.forEach(r=>r.total=r.bills+r.ins+r.sip);return rows}
function stackBars(rows){const w=320,h=190,pl=34,pr=6,pt=18,pb=24;const max=Math.max(...rows.map(r=>r.total),1);const bw=(w-pl-pr)/rows.length;let g='';
  [0,.5,1].forEach(f=>{const y=pt+(h-pt-pb)*(1-f);g+=`<line x1="${pl}" x2="${w-pr}" y1="${y}" y2="${y}" stroke="rgba(245,243,236,.08)"/><text x="${pl-5}" y="${y+3}" text-anchor="end">${cmp(max*f)}</text>`});
  const col={bills:'#16A765',ins:'#CBAA62',sip:'#B9C2CA'};
  rows.forEach((r,i)=>{let y=h-pb;const x=pl+i*bw+bw*.18,bwid=bw*.64;['bills','ins','sip'].forEach(k=>{const ht=(h-pt-pb)*r[k]/max;if(ht>0){y-=ht;g+=`<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bwid.toFixed(1)}" height="${ht.toFixed(1)}" fill="${col[k]}"/>`}});
    g+=`<text x="${(x+bwid/2).toFixed(1)}" y="${(y-4).toFixed(1)}" text-anchor="middle" class="tv" style="font-size:7px">${cmp(r.total)}</text><text x="${(x+bwid/2).toFixed(1)}" y="${h-8}" text-anchor="middle" style="font-size:8px">${monthShort(r.m)}</text>`});
  return `<svg class="chart" viewBox="0 0 ${w} ${h}" role="img" aria-label="Planned payments for the next 12 months">${g}</svg>`}
PAGES.yearplan=()=>{const rows=yearPlan(),tot=sum(rows,r=>r.total),avg=tot/12,hv=rows.reduce((a,b)=>b.total>a.total?b:a,rows[0]);
  const items=[...hv.items].sort((a,b)=>b.a-a.a).slice(0,7);
  return `${subtabs('yearplan')}${pageHead('Year plan','Everything you are due to pay over the next 12 months, so heavy months never surprise you.')}
  <div class="tiles" style="margin-bottom:14px"><div class="tile"><div class="l">Next 12 months</div><div class="v">${money(tot)}</div></div><div class="tile"><div class="l">Average per month</div><div class="v">${money(avg)}</div></div><div class="tile gold"><div class="l">Heaviest month</div><div class="v">${monthLabel(hv.m)}</div><div class="s">${money(hv.total)}</div></div></div>
  <div class="g2"><section class="card"><h2>Month by month</h2><div style="margin-top:8px">${stackBars(rows)}</div><div class="leg" style="margin-top:8px"><span><span class="dot" style="background:var(--pri)"></span>Bills &amp; EMIs</span><span><span class="dot" style="background:var(--gold)"></span>Insurance</span><span><span class="dot" style="background:var(--silver)"></span>SIPs</span></div></section>
  <section class="card"><h2>What makes up ${monthLabel(hv.m)}</h2><div class="list" style="margin-top:6px">${items.map(i=>`<div class="row"><div class="rmain" style="cursor:default;padding:9px 0"><span class="rt t1" style="font-weight:500">${esc(i.n)}</span><span class="amt">${money(i.a)}</span></div></div>`).join('')||emptyBox('Nothing planned')}</div></section></div>
  <section class="card" style="margin-top:14px"><h2>All months</h2><div class="list" style="margin-top:6px">${rows.map(r=>`<div class="row"><div class="rmain" style="cursor:default"><span class="rt"><span class="t1">${monthLabel(r.m)}</span><br><span class="t2">Bills ${money(r.bills)} · Insurance ${money(r.ins)} · SIPs ${money(r.sip)}</span></span><span class="ra"><span class="amt">${money(r.total)}</span>${r===hv?pill('gold','Heaviest'):r.total>avg*1.25?pill('warn','! Above average'):''}</span></div></div>`).join('')}</div></section>
  <p class="small muted" style="margin-top:12px">Based on your recurring bills, insurance premiums and SIPs. Loan EMIs are included through their bills. One-off costs you have not added are not included.</p>`};

/* ----- More & Settings ----- */
PAGES.more=()=>{const it=(ic_,t,s,a,r)=>`<button class="row" style="width:100%;background:none;border:0;border-top:1px solid var(--line);color:inherit;text-align:left;padding:14px 0" data-a="${a}" ${r?`data-r="${r}"`:''}><span class="av g">${ic(ic_,18)}</span><span class="rt"><span class="t1">${t}</span><br><span class="t2">${s}</span></span>${ic('chev',16)}</button>`;
  return `${pageHead('More','Settings, security and privacy.')}
  <section class="card"><div class="list">${it('bell','Reminders','Upcoming, missed and automatic alerts','go','reminders').replace('border-top:1px solid var(--line);','')}${it('gear','Settings, privacy & backup','Currency, notifications, app lock, export and restore','go','prefs')}${it('lock','Lock the app now','Locks immediately and asks for your PIN','lockNow')}${it('info','About and privacy','What is stored, what is not, and the limits','about')}</div></section>
  <section class="card" style="margin-top:14px"><h2>About</h2><p class="muted" style="margin-top:6px">My Life Manager 1.0. Private and offline. Your data is encrypted on this phone and is never uploaded. No account, no ads, no analytics.</p></section>`};
const sw=(k,on,act)=>`<button class="sw" role="switch" aria-checked="${on}" data-a="${act||'tg'}" data-k="${k}"><i></i><span>${on?'On':'Off'}</span></button>`;
const selOpts=(arr,cur)=>arr.map(([v,l])=>`<option value="${v}"${cur==v?' selected':''}>${l}</option>`).join('');
PAGES.prefs=()=>{const s=S.settings;
  return `${pageHead('Settings','Privacy, security and backup, explained plainly.')}
  <div class="g2">
  <section class="card"><h2>General</h2>
    <div class="srow"><div><div class="t1">Your name</div><div class="t2">Used in the welcome message.</div></div><div style="width:150px"><input id="setName" value="${esc(s.name)}" maxlength="30" aria-label="Your name" data-sel="name"></div></div>
    <div class="srow"><div><div class="t1">Currency</div><div class="t2">Changes the symbol only. No conversion is done.</div></div><div style="width:150px"><select data-sel="cur" aria-label="Currency">${Object.keys(CUR).map(c=>`<option${c===s.currency?' selected':''}>${c}</option>`).join('')}</select></div></div></section>
  <section class="card"><h2>App lock</h2>
    <div class="srow"><div><div class="t1">Fingerprint unlock</div><div class="t2">${ENV.bio||s.bio?'Uses your phone’s strong biometrics. Your PIN always works too.':'Not available. Set up a fingerprint on your phone first.'}</div></div>${ENV.bio||s.bio?sw('bio',s.bio,'toggleBio'):pill('','Unavailable')}</div>
    <div class="srow"><div><div class="t1">Lock when I leave the app</div><div class="t2">Applies when you switch to another app.</div></div><div style="width:150px"><select data-sel="leave" aria-label="Lock when leaving">${selOpts([[0,'Immediately'],[60,'After 1 minute'],[300,'After 5 minutes']],s.leaveLock)}</select></div></div>
    <div class="srow"><div><div class="t1">Auto-lock after</div><div class="t2">Inactivity while the app is open.</div></div><div style="width:150px"><select data-sel="auto" aria-label="Auto-lock">${selOpts([[1,'1 minute'],[5,'5 minutes'],[15,'15 minutes'],[0,'Never']],s.autoLock)}</select></div></div>
    <div class="srow"><div><div class="t1">PIN</div><div class="t2">Wrong attempts add waits: 30 seconds after 3, rising to 15 minutes.</div></div><button class="btn sm sec" data-a="chgPin">Change PIN</button></div></section>
  <section class="card"><h2>Notifications</h2>
    <div class="srow"><div><div class="t1">Reminders on this phone</div><div class="t2">Needs notification permission. Timing can be a few minutes off.</div></div>${sw('notif',s.notif,'toggleNotif')}</div>
    <div class="srow"><div><div class="t1">Hide details on lock screen</div><div class="t2">Shows “A payment is due soon” instead of names and amounts.</div></div>${sw('hideNotif',s.hideNotif)}</div>
    <div class="srow"><div><div class="t1">Bills</div></div>${sw('nBills',s.nBills)}</div><div class="srow"><div><div class="t1">Insurance renewals</div></div>${sw('nIns',s.nIns)}</div>
    <div class="srow"><div><div class="t1">Document expiry</div></div>${sw('nDocs',s.nDocs)}</div><div class="srow"><div><div class="t1">SIP dates</div></div>${sw('nSip',s.nSip)}</div>
    <div class="srow"><div><div class="t1">Bill reminder lead time</div></div><div style="width:150px"><select data-sel="adv" aria-label="Lead time">${[1,3,5,7].map(n=>`<option value="${n}"${s.adv==n?' selected':''}>${n} day${n>1?'s':''} before</option>`).join('')}</select></div></div>
    <div class="srow"><div><div class="t1">Check that it works</div><div class="t2">Sends a test reminder in about 5 seconds.</div></div><button class="btn sm sec" data-a="testNotif">Send test</button></div></section>
  <section class="card"><h2>Privacy and protection</h2>
    <div class="kv" style="margin-top:8px"><div class="full"><div class="l">Where your data lives</div><div class="v" style="font-weight:500">On this phone only. No account, no ads, no analytics, nothing uploaded.</div></div>
    <div><div class="l">Encryption</div><div class="v">AES-256-GCM</div></div><div><div class="l">Key protection</div><div class="v">${vault.keysAreHardwareBacked?pill('ok','PIN + Android Keystore'):pill('warn','PIN only (browser test)')}</div></div>
    <div><div class="l">Screenshots</div><div class="v">${isNative()?pill('ok','Blocked'):pill('','Android app only')}</div></div><div><div class="l">Cloud sync</div><div class="v">${pill('','Off')}</div></div></div></section>
  <section class="card span2"><h2>Backup, restore and deletion</h2>
    <p class="muted" style="margin:6px 0 12px">Nothing is copied anywhere unless you export it. A backup is a single file encrypted with a password you choose. Keep it somewhere safe, such as your email drafts or a cloud drive. Without the password it cannot be opened.</p>
    <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn sec" data-a="export">${ic('down')}Create encrypted backup</button><button class="btn sec" data-a="restore">${ic('up')}Restore from backup</button><button class="btn danger" data-a="wipe">${ic('trash')}Delete all data</button></div>
    <div class="note" style="margin-top:12px">${ic('info')}<div>Creating a backup, restoring, changing the PIN and deleting all ask for your PIN. If you forget the PIN, nobody can recover your data, so a backup matters.</div></div></section>
  </div>`};

/* ---------- forms ---------- */
const O=a=>a.map(x=>[x,x]);
const notFuture=l=>v=>v.date>TODAY?l+' cannot be in the future.':null;
function billForm(b){b=b||{};
  openForm({title:b.id?'Edit bill':'Add bill',vals:{...b,status:b.status||'unpaid'},label:b.id?'Save changes':'Add bill',fields:[
    {k:'name',label:'Bill or expense name',req:true,maxlen:60,ph:'e.g. Electricity bill'},
    {k:'amount',label:'Amount',t:'number',req:true,min:1,w:'half'},{k:'category',label:'Category',t:'select',opts:CATS,w:'half'},
    {k:'recurrence',label:'Repeats',t:'select',opts:REC,w:'half',def:'none'},{k:'customDays',label:'Every how many days',t:'number',min:1,max:365,showIf:['recurrence','custom'],w:'half',req:false,check:o=>o.recurrence==='custom'&&!o.customDays?'Enter the number of days.':null},
    {k:'dueDate',label:'Due date',t:'date',req:true,w:'half'},{k:'status',label:'Status',t:'select',opts:[['unpaid','Unpaid'],['paid','Paid']],showIf:['recurrence','none'],w:'half'},
    {k:'notes',label:'Notes',t:'textarea',maxlen:200},{k:'attach',label:'Invoice or receipt',t:'file',cur:b.attach,curId:b.attach_id,hint:'PDF, JPG or PNG, up to 10 MB.'}],
    save:v=>{const rec=v.recurrence||'none';const nb={...b,id:b.id||uid(),name:v.name,amount:v.amount,category:v.category,recurrence:rec,customDays:rec==='custom'?v.customDays:0,dueDate:v.dueDate,notes:v.notes,attach:v.attach,attach_id:v.attach_id,history:b.history||[]};
      if(rec==='none'){const was=b.status==='paid';nb.status=v.status==='paid'?'paid':'unpaid';if(nb.status==='paid'&&!was){nb.paidDate=TODAY;nb.history=[{date:TODAY,amount:nb.amount},...nb.history]}if(nb.status!=='paid')nb.paidDate=''}else{nb.status='unpaid';nb.paidDate=''}
      if(b.id)S.bills[S.bills.findIndex(x=>x.id===b.id)]=nb;else S.bills.push(nb);
      log((b.id?'Edited bill ':'Added bill ')+nb.name,'edit');persist();toast(b.id?'Bill updated':'Bill added');render(true)}})}
function insForm(p){p=p||{};
  openForm({title:p.id?'Edit policy':'Add insurance policy',vals:p,label:p.id?'Save changes':'Add policy',fields:[
    {k:'type',label:'Type',t:'select',opts:INS_TYPES,w:'half'},{k:'provider',label:'Insurance provider',req:true,maxlen:60,w:'half'},
    {k:'name',label:'Policy name',req:true,maxlen:60},
    {k:'number',label:'Policy number',req:true,maxlen:30,hint:'Stored privately. Shown masked until you confirm your PIN.',check:o=>/^[A-Za-z0-9\-\/]{4,30}$/.test(o.number)?null:'Use 4 to 30 letters, digits, dashes or slashes.'},
    {k:'coverage',label:'Coverage amount',t:'number',req:true,min:1,w:'half'},{k:'premium',label:'Premium amount',t:'number',req:true,min:1,w:'half'},
    {k:'freq',label:'Premium frequency',t:'select',opts:FREQ,def:'annual',w:'half'},{k:'start',label:'Policy start date',t:'date',req:true,w:'half'},
    {k:'expiry',label:'Expiry date',t:'date',req:true,w:'half',check:o=>o.start&&o.expiry<=o.start?'Expiry must be after the start date.':null},{k:'renewal',label:'Renewal date',t:'date',req:true,w:'half'},
    {k:'beneficiary',label:'Nominee or beneficiary',maxlen:80,w:'half'},{k:'owner',label:'Belongs to',t:'select',opts:FAMILY,w:'half',def:'Self'},
    {k:'policyDoc',label:'Policy document',t:'file',cur:p.policyDoc,curId:p.policyDoc_id,w:'half'},{k:'receipt',label:'Premium receipt',t:'file',cur:p.receipt,curId:p.receipt_id,w:'half'},{k:'notes',label:'Notes',t:'textarea',maxlen:200}],
    save:v=>{const n={...p,id:p.id||uid(),...v};delete n._size_policyDoc;delete n._size_receipt;if(p.id)S.ins[S.ins.findIndex(x=>x.id===p.id)]=n;else S.ins.push(n);
      log((p.id?'Edited policy ':'Added policy ')+n.name,'edit');persist();toast(p.id?'Policy updated':'Policy added');render(true)}})}
function invForm(i){i=i||{};
  openForm({title:i.id?'Edit investment':'Add investment',vals:i,label:i.id?'Save changes':'Add investment',fields:[
    {k:'name',label:'Investment name',req:true,maxlen:60},{k:'category',label:'Category',t:'select',opts:INV_CATS,w:'half'},{k:'platform',label:'Platform or broker',maxlen:40,w:'half'},
    {k:'invested',label:'Invested amount',t:'number',req:true,min:0,w:'half'},{k:'units',label:'Units',t:'number',min:0,w:'half'},
    {k:'purchaseDate',label:'Purchase date',t:'date',check:o=>o.purchaseDate&&o.purchaseDate>TODAY?'Purchase date cannot be in the future.':null},
    {k:'nominee',label:'Nominee',maxlen:60},{k:'sip',label:'SIP amount per month',t:'number',min:0,w:'half',hint:'Leave empty if there is no SIP.'},{k:'sipDay',label:'SIP date (day of month)',t:'number',min:1,max:28,w:'half',check:o=>o.sip>0&&!o.sipDay?'Enter the day of the month (1 to 28).':null},
    {k:'notes',label:'Notes',t:'textarea',maxlen:200}],
    save:v=>{const n={...i,id:i.id||uid(),name:v.name,category:v.category,platform:v.platform,nominee:v.nominee,invested:v.invested,units:+v.units||0,purchaseDate:v.purchaseDate||TODAY,sip:+v.sip||0,sipDay:+v.sipDay||0,notes:v.notes,txns:i.txns||[]};
      if(i.id)S.inv[S.inv.findIndex(x=>x.id===i.id)]=n;else S.inv.push(n);log((i.id?'Edited ':'Added investment ')+n.name,'inv');persist();toast(i.id?'Investment updated':'Investment added');render(true)}})}
function txnForm(id){const i=find('inv',id);
  openForm({title:'Add transaction',intro:esc(i.name),label:'Add transaction',vals:{date:TODAY},fields:[{k:'date',label:'Date',t:'date',req:true,w:'half',check:notFuture('Date')},{k:'amount',label:'Amount invested',t:'number',req:true,min:1,w:'half'},{k:'units',label:'Units bought',t:'number',min:0,w:'half'},{k:'note',label:'Note',maxlen:60,w:'half'}],
    save:v=>{i.txns.unshift({id:uid(),date:v.date,amount:v.amount,units:+v.units||0,note:v.note});i.invested+=v.amount;i.units=+(i.units+(+v.units||0)).toFixed(3);log(`Added ${money(v.amount)} to ${i.name}`,'inv');persist();toast('Transaction added');render(true);invDetail(id)}})}
function metalForm(k,it){it=it||{};const M=METAL[k];
  openForm({title:it.id?`Edit ${M.name.toLowerCase()} asset`:`Add ${M.name.toLowerCase()}`,vals:{...it,unit:'g'},label:it.id?'Save changes':'Add '+M.name.toLowerCase(),fields:[
    {k:'name',label:'Asset name',req:true,maxlen:60},{k:'kind',label:'Type',t:'select',opts:M.kinds,w:'half'},{k:'purity',label:'Purity',t:'select',opts:M.purities,w:'half',def:M.purities[0]},
    {k:'weight',label:'Weight',t:'number',req:true,min:0.001,w:'half'},{k:'unit',label:'Unit',t:'select',opts:k==='silver'?[['g','grams'],['kg','kilograms']]:[['g','grams']],w:'half'},
    {k:'date',label:'Purchase date',t:'date',req:true,w:'half',check:notFuture('Purchase date')},{k:'amount',label:'Total amount paid',t:'number',req:true,min:1,w:'half',hint:'Including making charges and GST.'},
    {k:'making',label:'Making charges',t:'number',min:0,w:'half',def:0},{k:'gst',label:'GST and other charges',t:'number',min:0,w:'half',def:0},
    {k:'seller',label:'Seller or shop',maxlen:60},
    {k:'invoice',label:'Invoice',t:'file',cur:it.invoice,curId:it.invoice_id,kinds:['pdf','png','jpg'],w:'half'},{k:'photo',label:'Photograph',t:'file',accept:'.jpg,.jpeg,.png',kinds:['jpg','png'],cur:it.photo,curId:it.photo_id,w:'half'},{k:'notes',label:'Notes',t:'textarea',maxlen:200}],
    save:v=>{const n={...it,id:it.id||uid(),name:v.name,kind:v.kind,purity:v.purity,weight:v.weight*(v.unit==='kg'?1000:1),date:v.date,making:+v.making||0,gst:+v.gst||0,amount:v.amount,seller:v.seller,invoice:v.invoice,invoice_id:v.invoice_id,photo:v.photo,photo_id:v.photo_id,notes:v.notes};
      const a=S[k];if(it.id)a[a.findIndex(x=>x.id===it.id)]=n;else a.push(n);log(`${it.id?'Edited':'Added'} ${M.name.toLowerCase()} ${n.name}`,k);persist();toast(it.id?'Asset updated':'Asset added');render(true)}})}
function docForm(d){d=d||{};
  openForm({title:d.id?'Edit document':'Add document',vals:{...d,remind:d.remind==null?30:d.remind},label:d.id?'Save changes':'Add document',fields:[
    {k:'name',label:'Document name',req:true,maxlen:60},{k:'category',label:'Category',t:'select',opts:DOC_CATS,w:'half'},{k:'owner',label:'Belongs to',t:'select',opts:FAMILY,w:'half',def:'Self'},
    {k:'issue',label:'Issue date',t:'date',w:'half',check:o=>o.issue&&o.issue>TODAY?'Issue date cannot be in the future.':null},{k:'expiry',label:'Expiry date',t:'date',w:'half',check:o=>o.issue&&o.expiry&&o.expiry<o.issue?'Expiry must be after the issue date.':null},
    {k:'remind',label:'Remind me before expiry',t:'select',opts:[[0,'No reminder'],[7,'7 days'],[30,'30 days'],[60,'60 days'],[90,'90 days']],w:'half'},
    {k:'file',label:'File',t:'file',req:!d.id,cur:d.file,curId:d.file_id,hint:'PDF, JPG or PNG, up to 10 MB.'},{k:'description',label:'Description',t:'textarea',maxlen:200}],
    save:v=>{const n={...d,id:d.id||uid(),name:v.name,category:v.category,owner:v.owner,issue:v.issue,expiry:v.expiry,remind:+v.remind||0,description:v.description,file:v.file,file_id:v.file_id,size:v._size_file||d.size||0};
      if(d.id)S.docs[S.docs.findIndex(x=>x.id===d.id)]=n;else S.docs.push(n);log((d.id?'Edited document ':'Added document ')+n.name,'doc');persist();toast(d.id?'Document updated':'Document added');render(true)}})}
function remForm(r){r=r||{};
  openForm({title:r.id?'Edit reminder':'Add reminder',vals:{time:'09:00',advance:0,...r,recurrence:r.recurrence||'none',custom:r.custom||''},label:r.id?'Save changes':'Add reminder',fields:[
    {k:'title',label:'Reminder',req:true,maxlen:80},{k:'date',label:'Date',t:'date',req:true,w:'half'},{k:'time',label:'Time',t:'time',req:true,w:'half'},
    {k:'recurrence',label:'Repeats',t:'select',opts:REC,w:'half'},{k:'custom',label:'Every how many days',t:'number',min:1,max:365,showIf:['recurrence','custom'],w:'half',check:o=>o.recurrence==='custom'&&!o.custom?'Enter the number of days.':null},
    {k:'advance',label:'Advance notice',t:'select',opts:[[0,'At the time'],[1,'1 day before'],[3,'3 days before'],[7,'7 days before']],w:'half'},{k:'notes',label:'Notes',t:'textarea',maxlen:200}],
    save:v=>{const dup=S.rem.find(x=>x.id!==r.id&&x.title.toLowerCase()===v.title.toLowerCase()&&x.date===v.date);if(dup){toast('A reminder with this name and date already exists.');return}
      const n={...r,id:r.id||uid(),title:v.title,date:v.date,time:v.time,recurrence:v.recurrence||'none',custom:+v.custom||0,advance:+v.advance||0,notes:v.notes,done:r.done||false};
      if(r.id)S.rem[S.rem.findIndex(x=>x.id===r.id)]=n;else S.rem.push(n);log((r.id?'Edited reminder ':'Added reminder ')+n.title,'edit');persist();toast(r.id?'Reminder updated':'Reminder added');render(true)}})}
const ENT={bills:{form:billForm,nm:b=>b.name},ins:{form:insForm,nm:p=>p.name},inv:{form:invForm,nm:i=>i.name},gold:{form:r=>metalForm('gold',r),nm:i=>i.name},silver:{form:r=>metalForm('silver',r),nm:i=>i.name},docs:{form:docForm,nm:d=>d.name},rem:{form:remForm,nm:r=>r.title},loans:{form:loanForm,nm:l=>l.name}};
const find=(e,id)=>S[e].find(x=>x.id===id);

/* ---------- detail views ---------- */
const head=t=>`<div class="mh"><h2>${esc(t)}</h2><button class="icon-btn" data-a="close" aria-label="Close">${ic('x')}</button></div>`;
const kvp=(l,v,full)=>`<div${full?' class="full"':''}><div class="l">${l}</div><div class="v">${v}</div></div>`;
const editDel=(e,id,extra)=>`<div class="mf"><button class="btn danger" data-a="del" data-e="${e}" data-id="${id}">${ic('trash',16)}Delete</button><button class="btn sec" data-a="edit" data-e="${e}" data-id="${id}">${ic('edit',16)}Edit</button>${extra||''}</div>`;
function billDetail(id){const b=find('bills',id);if(!b)return;const paid=b.status==='paid';
  openModal(head(b.name)+`<div class="kv">${kvp('Amount',`<span class="amt">${money(b.amount)}</span>`)}${kvp('Status',paid?pill('ok','✓ Paid'):dueInfo(b.dueDate))}${kvp('Category',esc(b.category))}${kvp('Repeats',esc(recName(b.recurrence,b.customDays)))}${kvp(paid?'Paid on':'Due date',fd(paid?b.paidDate:b.dueDate))}${kvp('Attachment',fileRef(b.attach,b.attach_id))}${b.notes?kvp('Notes',`<span style="font-weight:500">${esc(b.notes)}</span>`,1):''}</div>
  <h3 style="margin:18px 0 2px">Payment history</h3><div class="list">${b.history.slice(0,6).map(h=>`<div class="row"><div class="rmain" style="cursor:default;padding:8px 0"><span class="rt t2">${fd(h.date)}</span><span class="amt">${money(h.amount)}</span></div></div>`).join('')||'<p class="muted small" style="padding:8px 0">No payments recorded yet.</p>'}</div>`
  +editDel('bills',id,paid&&b.recurrence==='none'?`<button class="btn sec" data-a="unpay" data-id="${id}">Mark unpaid</button>`:(paid?'':`<button class="btn" data-a="pay" data-id="${id}">${ic('check',16)}Mark paid</button>`)))}
function insDetail(id){const p=find('ins',id);if(!p)return;
  openModal(head(p.name)+`<div class="eyebrow" style="margin:-8px 0 12px">${esc(p.type)} insurance · ${esc(p.provider)}</div><div class="kv">${kvp('Coverage',`<span class="amt">${money(p.coverage)}</span>`)}${kvp('Premium',`<span class="amt">${money(p.premium)}</span> <span class="muted small">${esc((FREQ.find(f=>f[0]===p.freq)||[0,''])[1].toLowerCase())}</span>`)}
  ${kvp('Policy number',`<span id="pn" data-id="${id}" class="num">•••• ${esc(p.number.slice(-4))}</span> <button class="link" data-a="reveal" data-id="${id}" style="margin-left:6px">${ic('eye',15)} Reveal</button>`,1)}
  ${kvp('Start date',fd(p.start))}${kvp('Expiry date',fd(p.expiry))}${kvp('Renewal',expInfo(p.renewal,45)+' '+fd(p.renewal))}${kvp('Nominee / beneficiary',esc(p.beneficiary||'—'))}${kvp('Belongs to',esc(p.owner||'Self'))}${kvp('Policy document',fileRef(p.policyDoc,p.policyDoc_id))}${kvp('Premium receipt',fileRef(p.receipt,p.receipt_id))}${p.notes?kvp('Notes',esc(p.notes),1):''}</div>`+editDel('ins',id))}
function invDetail(id){const i=find('inv',id);if(!i)return;
  openModal(head(i.name)+`<div class="kv">${kvp('Invested',`<span class="amt">${money(i.invested)}</span>`)}${kvp('Nominee',esc(i.nominee||'—'))}${kvp('Units',i.units?i.units.toLocaleString('en-IN',{maximumFractionDigits:3}):'—')}${kvp('Category',esc(i.category))}${kvp('Platform',esc(i.platform||'—'))}${kvp('SIP',i.sip>0?`${money(i.sip)} on day ${i.sipDay}`:'None')}${kvp('First purchase',fd(i.purchaseDate))}${i.notes?kvp('Notes',esc(i.notes),1):''}</div>
  <h3 style="margin:18px 0 2px">Transactions</h3><div class="list">${i.txns.slice(0,6).map(t=>`<div class="row"><div class="rmain" style="cursor:default;padding:8px 0"><span class="rt"><span class="t1" style="font-weight:500">${fd(t.date)}</span><br><span class="t2">${esc(t.note||'Purchase')}${t.units?' · '+t.units+' units':''}</span></span><span class="amt">${money(t.amount)}</span></div></div>`).join('')||'<p class="muted small" style="padding:8px 0">No transactions recorded.</p>'}</div>`
  +editDel('inv',id,`<button class="btn" data-a="addTxn" data-id="${id}">${ic('plus',16)}Add transaction</button>`))}
function metalDetail(k,id){const M=METAL[k],it=find(k,id);if(!it)return;
  openModal(head(it.name)+`<div class="eyebrow" style="margin:-8px 0 12px;color:${M.col}">${esc(it.kind)} · ${esc(it.purity)}</div><div class="kv">${kvp('Weight',`<span class="amt" style="color:${M.col}">${wt(it.weight)}</span>`)}${kvp('Amount paid',`<span class="amt">${money(it.amount)}</span>`)}${kvp('Bought on',fd(it.date))}${kvp('Seller',esc(it.seller||'—'))}${kvp('Making charges',money(it.making))}${kvp('GST and other',money(it.gst))}${kvp('Invoice',fileRef(it.invoice,it.invoice_id))}${kvp('Photograph',fileRef(it.photo,it.photo_id))}${it.notes?kvp('Notes',esc(it.notes),1):''}</div>`+editDel(k,id))}
function docDetail(id){const d=find('docs',id);if(!d)return;
  openModal(head(d.name)+`<div class="kv">${kvp('Category',esc(d.category))}${kvp('Belongs to',esc(d.owner||'Self'))}${kvp('Expiry',d.expiry?expInfo(d.expiry,d.remind||60):'No expiry')}${kvp('Issued',fd(d.issue))}${kvp('Expires',fd(d.expiry))}${kvp('Reminder',d.remind?d.remind+' days before expiry':'None')}${kvp('File',fileRef(d.file,d.file_id)+(d.size?` · ${(d.size/1048576).toFixed(2)} MB`:''))}${d.description?kvp('Description',`<span style="font-weight:500">${esc(d.description)}</span>`,1):''}</div>`
  +editDel('docs',id,`<button class="btn" data-a="openDoc" data-id="${id}">${ic('eye',16)}Open</button>`))}

/* ---------- lock, PIN, onboarding ---------- */
let cdTimer=null,keyH=null,lastActive=Date.now(),bgAt=0,bgGrace=false,graceUntil=0,padCtl=null,locking=false;
const hideApp=()=>{['#view','#side','#top','#bnav','#modalRoot','#modal2'].forEach(s=>{const e=$(s);if(e)e.innerHTML=''})};
function pinPad(o){
  if(padCtl)padCtl.close();
  const el=$('#lock');let pin='',busyP=false,waitUntil=0,closed=false,title=o.title||'',sub=o.sub||'';el.hidden=false;
  const N=4,dotsHTML=()=>Array.from({length:N},(_,i)=>`<i class="${i<pin.length?'on':''}"></i>`).join('');
  el.innerHTML=`<div class="lockbox">${logo(56)}<h1 id="ptitle"></h1><p class="muted" id="psub"></p>
    <div class="pdots" id="pdots" role="img" aria-label="PIN entry">${dotsHTML()}</div><div class="lmsg" id="lmsg" role="alert"></div>
    <div class="pad">${[1,2,3,4,5,6,7,8,9].map(n=>`<button data-p="${n}" aria-label="${n}">${n}</button>`).join('')}${o.cancel?'<button class="ghost" data-p="cancel">Cancel</button>':'<span></span>'}<button data-p="0" aria-label="0">0</button><button class="ghost" data-p="del" aria-label="Delete last digit">⌫</button></div>
    ${o.bio?`<button class="btn sec" data-p="bio">${ic('finger')}Use fingerprint</button>`:''}${o.extra?`<button class="link" data-p="extra" style="margin-top:12px">${esc(o.extra)}</button>`:''}</div>`;
  const dots=()=>{const d=$('#pdots');if(d)d.innerHTML=dotsHTML()};
  const ctl={cancelable:!!o.cancel,
    set(t,s){title=t;sub=s||'';$('#ptitle').textContent=title;$('#psub').textContent=sub},
    msg(t,bad){const m=$('#lmsg');if(m){m.textContent=t||'';m.className='lmsg'+(bad?' bad':'')}},
    shake(){const d=$('#pdots');if(d){d.classList.remove('shake');void d.offsetWidth;d.classList.add('shake')}},
    wait(ms){waitUntil=Date.now()+ms;clearInterval(cdTimer);const tick=()=>{if(closed)return;const left=Math.ceil((waitUntil-Date.now())/1000),dis=left>0;
        $$('.pad button[data-p]',el).forEach(b=>{if(/^\d$/.test(b.dataset.p))b.disabled=dis});
        if(dis)ctl.msg(`Too many attempts. Try again in ${left>=60?Math.ceil(left/60)+' min':left+' s'}.`,true);else{ctl.msg('You can try again.');clearInterval(cdTimer)}};tick();cdTimer=setInterval(tick,500)},
    bio(){if(o.onBio)o.onBio(ctl)},
    cancel(){ctl.close();o.onCancel&&o.onCancel()},
    close(){closed=true;clearInterval(cdTimer);el.hidden=true;el.innerHTML='';if(keyH)document.removeEventListener('keydown',keyH,true);keyH=null;if(padCtl===ctl)padCtl=null}};
  padCtl=ctl;ctl.set(title,sub);
  const press=k=>{
    if(k==='cancel'){ctl.cancel();return}
    if(k==='del'){pin=pin.slice(0,-1);dots();return}
    if(k==='bio'){ctl.bio();return}
    if(k==='extra'){o.onExtra&&o.onExtra(ctl);return}
    if(/^\d$/.test(k)&&!busyP&&pin.length<N&&Date.now()>=waitUntil){pin+=k;dots();
      if(pin.length===N){busyP=true;const p=pin;setTimeout(async()=>{try{await o.onPin(p,ctl)}catch(e){if(!closed)ctl.msg('Something went wrong. Try again.',true)}pin='';if(!closed)dots();busyP=false},80)}}};
  el.onclick=e=>{const b=e.target.closest('[data-p]');if(b&&!b.disabled)press(b.dataset.p)};
  keyH=e=>{if(/^\d$/.test(e.key))press(e.key);else if(e.key==='Backspace')press('del');else if(e.key==='Escape'&&o.cancel)press('cancel');else return;e.preventDefault();e.stopPropagation()};
  document.addEventListener('keydown',keyH,true);
  return ctl}
function newPinFlow({title,cancel,onDone,onCancel}){let first=null;const SUB='Choose 4 digits you will remember.';
  pinPad({title,sub:SUB,cancel,onCancel,onPin:async(pin,c)=>{
    if(first===null){const w=pinWeakness(pin);if(w){c.msg(w,true);c.shake();return}first=pin;c.set('Confirm your PIN','Enter it once more.');c.msg('');return}
    if(pin!==first){first=null;c.set(title,SUB);c.msg('The PINs did not match. Start again.',true);c.shake();return}
    const f=first;first=null;await onDone(f,c)}})}
function failMsg(r,c){
  if(r.reason==='wrong'){c.msg(`Incorrect PIN. ${r.attemptsBeforeWait} attempt${r.attemptsBeforeWait===1?'':'s'} left before a wait.`,true);c.shake()}
  else if(r.reason==='locked'){c.shake();c.wait(r.waitMs)}
  else if(r.reason==='format')c.msg('Enter 4 digits.',true);
  else{c.close();showDamaged()}}
async function showUnlock(){
  hideApp();
  const bioOn=(await vault.biometricEnabled())&&(await biometricAvailable());
  pinPad({title:'Welcome back',sub:'Enter your PIN to unlock.',bio:bioOn,extra:'Forgot PIN?',
    onPin:async(pin,c)=>{const r=await vault.unlockWithPin(pin);await afterAttempt(r,c)},
    onBio:async c=>{if(await confirmBiometric('Unlock My Life Manager')){await afterAttempt(await vault.unlockAfterBiometric(),c)}else c.msg('Fingerprint not recognised. Use your PIN.',true)},
    onExtra:()=>eraseScreen(()=>showUnlock(),'If you forgot your PIN, your data cannot be opened by anyone, including us. The only way forward is to erase this app’s data and start again, then restore an encrypted backup if you have one.')});
  const w=await vault.lockout.waitMs();if(w>0&&padCtl)padCtl.wait(w);else if(bioOn&&padCtl)setTimeout(()=>padCtl&&padCtl.bio(),300)}
async function afterAttempt(r,c){
  if(!r.ok){failMsg(r,c);return}
  try{await enterApp()}catch(e){c.close();if(e instanceof VaultDamagedError)showDamaged();else{showUnlock();toast('Could not open your data.')}}}
async function enterApp(){
  const txt=await vault.load();let st;
  if(txt===null)st=emptyState('');
  else{let p;try{p=parseState(txt)}catch(e){throw new VaultDamagedError()}st=adopt(p).state}
  st.settings.bio=await vault.biometricEnabled();
  S=st;showApp()}
function showApp(){if(padCtl)padCtl.close();const el=$('#lock');el.hidden=true;el.innerHTML='';refreshToday();lastActive=Date.now();bgAt=0;render();syncNotifs()}
function showDamaged(){hideApp();const el=$('#lock');el.hidden=false;
  el.innerHTML=`<div class="lockbox">${logo(56)}<h1>Your data cannot be read</h1><p class="muted">The stored data is damaged or was changed. Nothing has been sent anywhere. If you have an encrypted backup you can erase and restore it.</p><div class="mf" style="justify-content:center"><button class="btn sec" id="dTry">Try again</button><button class="btn danger" id="dErase">Erase and start over</button></div></div>`;
  $('#dTry').onclick=()=>showUnlock();$('#dErase').onclick=()=>eraseScreen(()=>showDamaged(),'This deletes the damaged data from this phone.')}
function eraseScreen(back,why){const el=$('#lock');el.hidden=false;
  el.innerHTML=`<div class="lockbox">${logo(56)}<h1>Erase everything?</h1><p class="muted" id="ewhy"></p><div class="fld" style="text-align:left;margin-top:12px;width:100%"><label for="etype">Type <b>ERASE</b> to continue</label><input id="etype" autocomplete="off"></div><div class="mf" style="justify-content:center"><button class="btn sec" id="eback">Go back</button><button class="btn danger" id="eyes" disabled>Erase all data</button></div></div>`;
  $('#ewhy').textContent=why;$('#eback').onclick=()=>{el.innerHTML='';back()};
  $('#etype').addEventListener('input',e=>{$('#eyes').disabled=e.target.value.trim()!=='ERASE'});
  $('#eyes').onclick=async()=>{busy('Erasing…');try{await cancelAllScheduled().catch(()=>{});await vault.wipe();S=null}catch(e){busy(false);toast('Could not erase. Try again.');return}busy(false);showOnboarding()}}
function ask({title,text,yes,no}){return new Promise(res=>{const el=$('#lock');el.hidden=false;
  el.innerHTML=`<div class="lockbox">${logo(56)}<h1 id="at"></h1><p class="muted" id="ax"></p><div class="mf" style="justify-content:center"><button class="btn sec" id="an"></button><button class="btn" id="ay"></button></div></div>`;
  $('#at').textContent=title;$('#ax').textContent=text;$('#an').textContent=no;$('#ay').textContent=yes;
  $('#ay').onclick=()=>{el.innerHTML='';res(true)};$('#an').onclick=()=>{el.innerHTML='';res(false)}})}
function showOnboarding(){hideApp();const el=$('#lock');el.hidden=false;
  el.innerHTML=`<div class="lockbox">${logo(64)}<h1>My Life Manager</h1><p class="muted">Your bills, insurance, investments, gold, silver and documents in one private place. Everything stays on this phone, encrypted. No account, no ads, no tracking.</p>
    <div class="fld" style="text-align:left;margin-top:16px;width:100%"><label for="obName">What should we call you?</label><input id="obName" maxlength="30" autocomplete="off"><div class="err" id="obErr" role="alert"></div></div>
    <div class="mf" style="justify-content:center"><button class="btn" id="obGo">Continue</button></div>
    <p class="small muted" style="margin-top:12px">Next you choose a 4-digit PIN. It cannot be recovered if you forget it, so make an encrypted backup once you have added data.</p></div>`;
  const go=()=>{const n=$('#obName').value.trim().slice(0,30);if(!n){$('#obErr').textContent='Please enter a name.';$('#obName').parentElement.classList.add('bad');return}choosePin(n)};
  $('#obGo').onclick=go;$('#obName').addEventListener('keydown',e=>{if(e.key==='Enter')go()})}
function choosePin(name){newPinFlow({title:'Create your PIN',cancel:false,onDone:async(pin,c)=>{
  c.msg('Securing your vault…');await new Promise(r=>setTimeout(r,40));
  try{await vault.create(pin);S=emptyState(name);await vault.save(JSON.stringify(S))}catch(e){c.msg('Could not set up secure storage on this device.',true);return}
  c.close();await onboardExtras(pin)}})}
async function onboardExtras(pin){
  if(ENV.bio&&await ask({title:'Unlock with fingerprint?',text:'You can unlock with your fingerprint instead of typing the PIN. Your PIN still works.',yes:'Turn on',no:'Not now'})){
    if(await confirmBiometric('Turn on fingerprint unlock')){const r=await vault.enableBiometric(pin);if(r.ok)S.settings.bio=true}}
  if(isNative()&&await ask({title:'Get reminders?',text:'Allow notifications so your phone can remind you about bills, renewals and expiring documents. They are created on this phone only.',yes:'Allow',no:'Not now'})){
    if(await notificationPermission(true)==='granted')S.settings.notif=true}
  persist();await saveChain;showApp();toast('Welcome, '+S.settings.name)}
function reauth(cb,opt){opt=opt||{};const bioOk=S.settings.bio&&!opt.pinOnly&&ENV.bio;
  const run=pin=>{Promise.resolve().then(()=>cb(pin)).catch(()=>toast('Something went wrong.'))};
  pinPad({cancel:true,title:'Confirm it’s you',sub:'This action needs your PIN.',bio:bioOk,
    onPin:async(pin,c)=>{const r=await vault.verifyPin(pin);if(r.ok){c.close();run(pin)}else failMsg(r,c)},
    onBio:async c=>{if(await confirmBiometric('Confirm it is you')){c.close();run()}else c.msg('Fingerprint not recognised.',true)}})}
async function lockNow(){
  if(!S||locking)return;locking=true;
  try{closeModal();closeModal(2);const pend=saveChain;if(notifTimer){clearTimeout(notifTimer);notifTimer=null;syncNotifs()}
    hideApp();S=null;await pend.catch(()=>{})}finally{vault.lock();locking=false}
  showUnlock()}
function onBackground(){if(!S)return;bgAt=Date.now();bgGrace=Date.now()<graceUntil;if(S.settings.leaveLock===0&&!bgGrace)lockNow()}
function onForeground(){if(!S)return;refreshToday();
  if(!bgGrace&&bgAt&&S.settings.leaveLock>0&&Date.now()-bgAt>=S.settings.leaveLock*1000){lockNow();return}
  if(S.settings.autoLock>0&&Date.now()-lastActive>S.settings.autoLock*60000){lockNow();return}
  bgAt=0;render(true)}
function onBack(){
  if(!$('#lock').hidden){if(padCtl&&padCtl.cancelable)padCtl.cancel();else minimizeApp();return}
  if($('#modal2').firstChild){closeModal(2);return}
  if($('#modalRoot').firstChild){closeModal();return}
  if(S&&cur()!=='home'){location.hash='home';return}
  minimizeApp()}
/* ---------- reminders → local notifications (created on this phone only) ---------- */
function at(date,time){const[y,m,d]=date.split('-').map(Number);const[h,mi]=(/^\d{2}:\d{2}$/.test(time||'')?time:'09:00').split(':').map(Number);return new Date(y,m-1,d,h,mi)}
function plannedNotes(){const s=S.settings,hide=s.hideNotif,out=[],T='My Life Manager';
  const add=(key,date,time,generic,detail)=>out.push({key,at:at(date,time),title:T,body:hide?generic:detail});
  S.rem.filter(r=>!r.done).forEach(r=>{let d=r.date;const n=r.recurrence==='none'?1:12;
    for(let i=0;i<n;i++){add(`rem:${r.id}:${d}`,addD(d,-(r.advance||0)),r.time,'You have a reminder',r.title);d=stepRec(d,r.recurrence,r.custom,1)}});
  if(s.nBills)unpaid().forEach(b=>{let d=b.dueDate;const n=b.recurrence==='none'?1:3;
    for(let i=0;i<n;i++){add(`bill:${b.id}:${d}`,addD(d,-s.adv),'09:00','A payment is due soon',`${b.name} · ${money(b.amount)} due ${fds(d)}`);d=stepRec(d,b.recurrence,b.customDays,1)}});
  if(s.nIns)S.ins.forEach(p=>{[30,7].forEach(k=>add(`ins:${p.id}:${k}`,addD(p.renewal,-k),'09:00','A policy renewal is coming up',`${p.name} renews on ${fds(p.renewal)}`))});
  if(s.nDocs)S.docs.filter(d=>d.expiry&&d.remind>0).forEach(d=>add(`doc:${d.id}:${d.expiry}`,addD(d.expiry,-d.remind),'09:00','A document is expiring soon',`${d.name} expires ${fds(d.expiry)}`));
  if(s.nSip)S.inv.filter(i=>i.sip>0&&i.sipDay).forEach(i=>{for(let k=0;k<3;k++){const dt=new Date(T0.getFullYear(),T0.getMonth()+k,Math.min(i.sipDay,28)),ds=iso(dt);add(`sip:${i.id}:${ds}`,addD(ds,-1),'09:00','An investment date is coming up',`${i.name} · ${money(i.sip)} on ${fds(ds)}`)}});
  return out}
async function syncNotifs(){if(!S||!S.settings.notif)return;const notes=plannedNotes();
  try{if(await notificationPermission(false)!=='granted')return;await replaceScheduled(notes)}catch(e){}}

/* ---------- chrome & routing ---------- */
const cur=()=>{const h=location.hash.slice(1);return PAGES[h]?h:'home'};
const NAV=[['home','Home','home'],['finance','Finance','wallet','bills'],['assets','Assets','trend','invest'],['docs','Documents','folder','docs'],['more','More','more','more']];
function renderChrome(){const r=cur(),g=groupOf(r);
  $('#bnav').innerHTML=NAV.map(([k,l,i,to])=>`<button data-a="go" data-r="${to||k}" ${g===k?'aria-current="page"':''}>${ic(i,22)}${l}</button>`).join('');
  const sd=(r_,l,i)=>`<button data-a="go" data-r="${r_}" ${r===r_?'aria-current="page"':''}>${ic(i,18)}${l}</button>`;
  $('#side').innerHTML=`<div class="brand">${LOGO}<span>My Life Manager</span></div>${sd('home','Home','home')}<h4>Finance</h4>${sd('bills','Bills & Expenses','wallet')}${sd('loans','Loans','cal')}${sd('insurance','Insurance','shield')}${sd('yearplan','Year plan','pie')}${sd('reminders','Reminders','bell')}<h4>Assets</h4>${sd('invest','Investments & SIPs','trend')}${sd('gold','Gold','coin')}${sd('silver','Silver','coin')}${sd('metals','Precious Metals','pie')}<h4>Vault</h4>${sd('docs','Documents','folder')}<h4>System</h4>${sd('prefs','Settings','gear')}<button data-a="lockNow">${ic('lock',18)}Lock app</button><p class="foot">Private and offline. Encrypted on this phone.</p>`;
  $('#top').innerHTML=`<div class="brand m">${LOGO}<span>My Life Manager</span></div><div class="sp"></div><button class="icon-btn" data-a="lockNow" aria-label="Lock app">${ic('lock')}</button>`}
function render(keep){if(!S)return;const v=$('#view'),y=window.scrollY;v.innerHTML=PAGES[cur()]();renderChrome();
  if(keep){window.scrollTo(0,y)}else{window.scrollTo(0,0);v.classList.remove('in');void v.offsetWidth;v.classList.add('in')}
  document.title='My Life Manager'}
window.addEventListener('hashchange',()=>render());

/* ---------- actions ---------- */
function payBill(id){const b=find('bills',id);if(!b)return;b.history.unshift({date:TODAY,amount:b.amount});
  if(b.recurrence==='none'){b.status='paid';b.paidDate=TODAY;toast(`${b.name} marked as paid`)}else{b.dueDate=stepRec(b.dueDate,b.recurrence,b.customDays,1);toast(`Paid ${money(b.amount)}. Next due ${fds(b.dueDate)}`)}
  log(`Paid ${b.name} · ${money(b.amount)}`,'pay');persist();closeModal();render(true)}
const A={
  go:d=>{closeModal();closeModal(2);if(location.hash==='#'+d.r)render();else location.hash=d.r},
  close:()=>closeModal(),close2:()=>closeModal(2),
  dismissIntro:()=>{S.settings.intro=true;persist();render(true)},
  addBill:()=>billForm(),addIns:()=>insForm(),addInv:()=>invForm(),addGold:()=>metalForm('gold'),addSilver:()=>metalForm('silver'),addDoc:()=>docForm(),addRem:()=>remForm(),addLoan:()=>loanForm(),loan:d=>loanDetail(d.id),updBal:d=>{closeModal();balForm(d.id)},
  bill:d=>billDetail(d.id),ins:d=>insDetail(d.id),inv:d=>invDetail(d.id),metal:d=>metalDetail(d.m,d.id),doc:d=>docDetail(d.id),remEdit:d=>remForm(find('rem',d.id)),
  pay:d=>payBill(d.id),
  unpay:d=>{const b=find('bills',d.id);const i=b.history.findIndex(h=>h.date===b.paidDate);if(i>-1)b.history.splice(i,1);b.status='unpaid';b.paidDate='';log(`Marked ${b.name} unpaid`,'edit');persist();closeModal();toast('Marked as unpaid');render(true)},
  edit:d=>{closeModal();ENT[d.e].form(find(d.e,d.id))},
  del:d=>{const r=find(d.e,d.id);closeModal();confirmBox({title:'Delete this record?',text:`“${esc(ENT[d.e].nm(r))}” will be removed from this device. This cannot be undone.`,yes:'Delete',danger:true,onYes:()=>{fileIdsOf(r).forEach(id=>vault.deleteFile(id).catch(()=>{}));S[d.e]=S[d.e].filter(x=>x.id!==d.id);log('Deleted '+ENT[d.e].nm(r),'del');persist();toast('Deleted');render(true)}})},
  bTab:d=>{UI.bills.tab=d.t;render(true)},bMode:d=>{UI.bills.mode=d.m;render(true)},bFilter:d=>{UI.bills.f=d.f;render(true)},
  iType:d=>{UI.ins.t=d.t;render(true)},iFilter:d=>{UI.inv.c=d.c;render(true)},dCat:d=>{UI.docs.c=d.c;render(true)},
  mTab:d=>{UI[d.m].tab=d.t;render(true)},mKind:d=>{UI[d.m].k=d.x;render(true)},remTab:d=>{UI.rem.tab=d.t;if(cur()!=='reminders')location.hash='reminders';else render(true)},
  
  addTxn:d=>{closeModal();txnForm(d.id)},
  remDone:d=>{const r=find('rem',d.id);if(r.done){r.done=false}else if(r.recurrence!=='none'){r.date=stepRec(r.date,r.recurrence,r.custom,1);toast('Done. Next reminder '+fds(r.date))}else{r.done=true;toast('Marked as done')}persist();render(true)},
  reveal:d=>reauth(()=>{const p=find('ins',d.id),el=$('#pn');if(!el)return;el.textContent=p.number;setTimeout(()=>{const e2=$('#pn');if(e2&&e2.dataset.id===d.id)e2.textContent='•••• '+p.number.slice(-4)},15000);toast('Shown for 15 seconds')}),
  tg:d=>{const k=d.k;if(typeof S.settings[k]!=='boolean')return;S.settings[k]=!S.settings[k];persist();render(true)},
  lockNow:()=>lockNow(),
  chgPin:()=>reauth(oldPin=>newPinFlow({title:'Choose a new PIN',cancel:true,onDone:async(pin,c)=>{c.msg('Updating…');const r=await vault.changePin(oldPin,pin);if(r.ok){c.close();toast('PIN changed')}else c.msg('Could not change the PIN. Try again.',true)}}),{pinOnly:true}),
  toggleBio:()=>{if(S.settings.bio)reauth(async()=>{await vault.disableBiometric();S.settings.bio=false;persist();render(true);toast('Fingerprint unlock turned off')},{pinOnly:true});
    else reauth(async pin=>{if(!(await confirmBiometric('Turn on fingerprint unlock'))){toast('Fingerprint was not confirmed');return}const r=await vault.enableBiometric(pin);if(r.ok){S.settings.bio=true;persist();render(true);toast('Fingerprint unlock turned on')}else toast('Could not turn it on')},{pinOnly:true})},
  toggleNotif:async()=>{if(S.settings.notif){S.settings.notif=false;persist();render(true);await cancelAllScheduled().catch(()=>{});toast('Reminders turned off');return}
    const p=await notificationPermission(true);if(!S)return;
    if(p==='granted'){S.settings.notif=true;persist();render(true);toast('Reminders turned on')}else if(p==='denied')toast('Notifications are blocked. Allow them in Android settings.');else toast('Reminders work in the Android app only.')},
  testNotif:async()=>{if(await notificationPermission(false)!=='granted'){toast('Turn on reminders first.');return}await sendTest(5);toast('A test reminder will arrive in about 5 seconds')},
  export:()=>reauth(()=>openModal(head('Create encrypted backup')+`<p class="muted small" style="margin-bottom:10px">Choose a backup password of at least 10 characters. You need it to restore, and it cannot be recovered. It is separate from your PIN, so make it strong.</p>
    <div class="fld"><label for="bkPw">Backup password</label><input id="bkPw" type="password" autocomplete="new-password"></div><div class="fld" style="margin-top:10px"><label for="bkPw2">Repeat password</label><input id="bkPw2" type="password" autocomplete="new-password"><div class="err" id="bkErr" role="alert"></div></div>
    <div class="mf"><button class="btn sec" data-a="close">Cancel</button><button class="btn" data-a="doExport">Create backup</button></div>`)),
  doExport:async()=>{const pw=$('#bkPw').value,pw2=$('#bkPw2').value,er=$('#bkErr');const m=checkBackupPassword(pw);if(m){er.textContent=m;return}if(pw!==pw2){er.textContent='The passwords do not match.';return}
    busy('Encrypting your backup…');
    try{const files=[];for(const id of await vault.fileIds())files.push({id,bytes:await vault.getFile(id)});
      const bytes=await createBackup(JSON.stringify(S),files,pw);graceUntil=Date.now()+90000;await deliverBackup(`my-life-manager-${TODAY}.mlmbackup`,bytes);closeModal();toast('Encrypted backup created')}
    catch(e){er.textContent='The backup was not saved. Try again.'}finally{busy(false)}},
  restore:()=>reauth(()=>openModal(head('Restore from backup')+`<p class="muted small" style="margin-bottom:10px">Choose a backup file made by this app and enter its password. Restoring replaces everything stored on this phone.</p>
    <div class="fld"><label for="rsFile">Backup file</label><input id="rsFile" type="file"></div><div class="fld" style="margin-top:10px"><label for="rsPw">Backup password</label><input id="rsPw" type="password" autocomplete="off"><div class="err" id="resErr" role="alert"></div></div>
    <div class="mf"><button class="btn sec" data-a="close">Cancel</button><button class="btn" data-a="doRestore">Check backup</button></div>`),{pinOnly:true}),
  doRestore:async()=>{const er=$('#resErr'),f=$('#rsFile').files[0],pw=$('#rsPw').value;
    if(!f){er.textContent='Choose a backup file.';return}if(f.size>300*1048576){er.textContent='This file is too large to be a backup.';return}if(!pw){er.textContent='Enter the backup password.';return}
    busy('Checking the backup…');let rd,parsed;
    try{rd=await readBackup(new Uint8Array(await f.arrayBuffer()),pw);parsed=adopt(parseState(rd.stateJson));
      for(const x of rd.files){const k=sniff(x.bytes);const v=validateUpload('x.'+(k==='jpg'?'jpg':k||'bin'),x.bytes);if(!v.ok)throw new BackupError('The backup contains a file that is not allowed.')}}
    catch(e){busy(false);er.textContent=e instanceof BackupError?e.message:'This backup could not be read.';return}
    busy(false);closeModal();const st=parsed.state,n=COLL.reduce((a,c)=>a+st[c].length,0);
    confirmBox({title:'Replace current data?',text:`Everything on this phone will be replaced by the backup (${n} records, ${rd.files.length} files).${parsed.dropped?` ${parsed.dropped} damaged records were skipped.`:''}`,yes:'Restore',danger:true,onYes:async()=>{
      busy('Restoring…');try{st.settings.bio=await vault.biometricEnabled();await vault.replaceAll(JSON.stringify(st),rd.files);S=st;busy(false);toast('Backup restored');render();syncNotifs()}catch(e){busy(false);toast('Restore failed. Your current data was not changed.')}}})},
  wipe:()=>reauth(()=>confirmBox({title:'Delete all data?',text:'Every record, attached file and setting on this phone will be erased, including the encryption keys. Create a backup first if you may need it.',typed:'DELETE',yes:'Delete everything',danger:true,onYes:async()=>{
    busy('Deleting…');try{await cancelAllScheduled().catch(()=>{});await vault.wipe()}finally{busy(false)}S=null;closeModal();closeModal(2);hideApp();showOnboarding()}}),{pinOnly:true}),
  about:()=>openModal(head('About and privacy')+`<div class="kv"><div class="full"><div class="l">What is stored</div><div class="v" style="font-weight:500">Only what you type and attach, encrypted on this phone. Nothing is uploaded and the app has no internet permission.</div></div>
    <div class="full"><div class="l">How it is protected</div><div class="v" style="font-weight:500">Your PIN (hardened with Argon2id) and a secret kept in the Android Keystore unlock a key that encrypts your data and files with AES-256-GCM. Wrong PINs cause growing waits.</div></div>
    <div class="full"><div class="l">Honest limits</div><div class="v" style="font-weight:500">A 4-digit PIN is a small space, and no app can promise to be unhackable. A rooted or compromised phone, or someone who knows your PIN, can still get in. Keep your phone updated and use a screen lock.</div></div></div><div class="mf"><button class="btn" data-a="close">Close</button></div>`),
  viewFile:d=>viewFile(d.id,d.n),
  openDoc:d=>{const x=find('docs',d.id);if(x)viewFile(x.file_id,x.file)},
};

/* ---------- events ---------- */
document.addEventListener('click',e=>{
  const bd=e.target.closest('[data-a="bd"]');if(bd&&e.target===bd){closeModal(bd.parentElement.id==='modal2'?2:1);return}
  const a=e.target.closest('[data-a]');if(!a||a.dataset.a==='bd')return;const f=A[a.dataset.a];if(f){e.preventDefault();f(a.dataset,a)}});
document.addEventListener('input',e=>{const q=e.target.dataset&&e.target.dataset.q;if(!q)return;const map={bills:['bills',billList],inv:['inv',invList],docs:['docs',docList]}[q];
  if(!map)return;(q==='inv'?UI.inv:q==='docs'?UI.docs:UI.bills).q=e.target.value;$('#list').innerHTML=map[1]()});
document.addEventListener('change',e=>{const k=e.target.dataset&&e.target.dataset.sel;if(!k)return;const v=e.target.value;
  if(k==='iOwn'){UI.ins.p=v;render(true)}else if(k==='dOwn'){UI.docs.p=v;render(true)}else if(k==='bCat'){UI.bills.cat=v;render(true)}else if(k==='bMonth'){UI.bills.month=v;render(true)}else if(k==='bYear'){UI.bills.year=v;render(true)}
  else if(k==='cur'&&CUR[v]){S.settings.currency=v;persist();render(true);toast('Currency symbol changed to '+v)}
  else if(k==='auto'){const n=+v;if([0,1,5,15].includes(n)){S.settings.autoLock=n;persist();toast('Auto-lock updated')}}else if(k==='leave'){const n=+v;if([0,60,300].includes(n)){S.settings.leaveLock=n;persist();toast('Updated')}}else if(k==='adv'){S.settings.adv=+v;persist();toast('Lead time updated')}
  else if(k==='name'){const n=v.trim().slice(0,30);if(n){S.settings.name=n;persist();toast('Name updated')}else{e.target.value=S.settings.name;toast('Name cannot be empty')}}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('#lock').hidden){if($('#modal2').firstChild)closeModal(2);else if($('#modalRoot').firstChild)closeModal()}});
['pointerdown','keydown','scroll'].forEach(ev=>window.addEventListener(ev,()=>{lastActive=Date.now()},{passive:true}));
setInterval(()=>{if(S&&S.settings.autoLock>0&&Date.now()-lastActive>S.settings.autoLock*60000)lockNow()},5000);

/* ---------- boot ---------- */
export async function start(){
  document.addEventListener('click',e=>{if(e.target.matches&&e.target.matches('input[type=file]'))graceUntil=Date.now()+90000},true);
  try{ENV.bio=await biometricAvailable();
    await watchLifecycle({onBackground,onForeground,onBack});
    if(await vault.exists())await showUnlock();else showOnboarding()}
  catch(e){const el=$('#lock');el.hidden=false;el.innerHTML='<div class="lockbox"><h1>Storage is not available</h1><p class="muted">The app could not open its private storage on this device. Close the app and try again.</p></div>'}}
if(import.meta.env.MODE==='test'){window.__mlm={state:()=>S&&JSON.parse(JSON.stringify(S)),
  inject:o=>{if(!S)throw new Error('locked');const a=adopt(parseState(JSON.stringify(o)));S=a.state;persist();render()},
  lock:()=>lockNow(),today:()=>TODAY,notes:()=>S?plannedNotes().map(n=>({key:n.key,at:n.at.getTime(),title:n.title,body:n.body})):null}}