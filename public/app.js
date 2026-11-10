// Idea y desarrollo: Yaiza Rios (Cyberzaintza). Todos los derechos reservados.
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let results = [];

const mail = (e) => `<span class="mail">${esc(e)} <button class="sec" data-copy="${esc(e)}">Copiar</button></span>`;
const link = (u, t) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t || u)}</a>`;
const dt = (s) => (s ? esc(String(s).slice(0, 10)) : '—');

function esUrl(domain) {
  const l = domain.split('.');
  const sld = ['com', 'nom', 'org', 'gob', 'edu'];
  const n = l.length;
  const name = (n >= 3 && sld.includes(l[n - 2])) ? l[n - 3] + '.' + l[n - 2] : l[n - 2];
  return 'https://nic.es/sgnd/dominio/publicBuscarDominios.action?tDominio.nombreDominio=' + encodeURIComponent(name) + '&flag=activado';
}

function formBtns(forms) {
  const out = [];
  for (const f of forms) {
    const urls = f.url ? [[f.url, 'Abrir formulario']] : (f.links || []).slice(0, 2).map(l => [l.url, l.text || 'Abrir']);
    for (const [u, t] of urls) out.push(`<a class="btn" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(f.name)}: ${esc(t)} ↗</a>`);
  }
  return out;
}

function whereBox(r) {
  const reg = r.registry;
  const regForms = r.forms.filter(f => f.scope === 'Registrador');
  const hostForms = r.forms.filter(f => f.scope !== 'Registrador');
  const regMails = reg?.abuse.emails || [];
  const hostMails = new Set();
  r.hosting.networks.forEach(n => n.abuse.emails.forEach(e => hostMails.add(e)));

  // 1) AGENTE REGISTRADOR (el dominio)
  let rg = '';
  if (reg?.registrar) rg += `<div class="act"><span class="lab">Agente registrador</span><strong>${esc(reg.registrar)}</strong>${reg.ianaId ? ' <span class="sub">(IANA ' + esc(reg.ianaId) + ')</span>' : ''}</div>`;
  if (reg?.created || reg?.expires) rg += `<div class="act"><span class="lab">Fecha de creación</span><strong>${dt(reg.created)}</strong>${reg.expires ? ' <span class="sub">· expira ' + dt(reg.expires) + '</span>' : ''}</div>`;
  if (regMails.length) rg += `<div class="act"><span class="lab">Email abuse</span>${regMails.map(mail).join('')}</div>`;
  if (reg?.abuse.phones?.filter(Boolean).length) rg += `<div class="act"><span class="lab">Teléfono abuse</span>${reg.abuse.phones.filter(Boolean).map(esc).join(', ')}</div>`;
  const rf = formBtns(regForms);
  if (rf.length) rg += `<div class="act"><span class="lab">Formulario</span>${rf.join('')}</div>`;
  else if (reg) rg += `<div class="act"><span class="lab">Formulario</span><span class="sub">No consta formulario del registrador${reg.registrarUrl ? ' · web: ' + link(reg.registrarUrl) : ''}</span></div>`;
  if (r.tld === 'es') rg += `<div class="act"><span class="lab">Registro .es (Red.es)</span><a class="btn" href="${esc(esUrl(r.domain))}" target="_blank" rel="noopener noreferrer">Ver titular y agente registrador en nic.es ↗</a></div><div class="act"><small class="sub">Se abre la lista de dominios ya buscada: pulsa «Ver datos» en el activo, luego «Continuar» (ahí Red.es pide un captcha que debe resolver una persona).</small></div>`;
  if (!rg) rg = `<div class="act"><span class="sub">No se ha podido obtener el registrador de este dominio automáticamente.</span></div>`;

  // 2) HOSTING / CDN (el contenido)
  let hs = '';
  const net = r.hosting.networks[0];
  if (net) hs += `<div class="act"><span class="lab">Red / hosting</span><strong>${esc(net.org || net.name)}</strong> <span class="sub">${esc(net.name)} · ${esc(net.ip)}</span></div>`;
  if (net) {
    // dónde se ha localizado: país de la IP, web del proveedor (dominio del email abuse) y registro de la IP
    const FREE = /^(gmail|hotmail|outlook|yahoo|live|icloud|proton|protonmail)\./i;
    const dom = [...hostMails].map(m => m.split('@')[1]).find(d => d && !FREE.test(d));
    let pais = '';
    try { pais = net.country ? new Intl.DisplayNames(['es'], { type: 'region' }).of(net.country.toUpperCase()) : ''; } catch {}
    const btns = [];
    if (dom) btns.push(`<a class="btn" href="https://${esc(dom)}" target="_blank" rel="noopener noreferrer">Web del hosting: ${esc(dom)} ↗</a>`);
    btns.push(`<a class="btn sec2" href="https://www.whois.com/whois/${encodeURIComponent(net.ip)}" target="_blank" rel="noopener noreferrer">Ver registro de la IP ${esc(net.ip)} ↗</a>`);
    hs += `<div class="act banner"><span class="lab">Dónde se ha localizado</span><div>${pais ? `<div class="sub">País de la IP: <strong>${esc(pais)}</strong>${net.range ? ' · rango ' + esc(net.range) : ''}</div>` : ''}<div class="bbtns">${btns.join('')}</div></div></div>`;
  }
  if (hostMails.size) hs +=`<div class="act"><span class="lab">Email abuse</span>${[...hostMails].map(mail).join('')}</div>`;
  const hf = formBtns(hostForms);
  if (hf.length) hs += `<div class="act"><span class="lab">Formulario</span>${hf.join('')}</div>`;
  const cdn = hostForms.some(f => /cloudflare/i.test(f.name)) || r.hosting.networks.some(n => /cloudflare|fastly|akamai|cloudfront|amazon-cf/i.test(n.name + ' ' + n.org));
  if (cdn) hs += `<div class="act"><small class="sub">Ojo: el dominio va detrás de un CDN/proxy, así que este es el contacto del CDN, no el del servidor real.</small></div>`;

  return `<div class="where"><h3>1 · Agente registrador — para reportar el dominio</h3>${rg}</div>` +
    (hs ? `<div class="where host"><h3>2 · Hosting / CDN — para reportar el contenido</h3>${hs}</div>` : '');
}

function render(r) {
  if (r.error) return `<div class="card"><h2>${esc(r.input)}</h2><div class="badges"><span class="b bad">${esc(r.error)}</span></div></div>`;
  const reg = r.registry, h = r.hosting;
  const regMails = reg?.abuse.emails || [];
  const badges = [];
  if (r.notRegistered) badges.push('<span class="b warn">Dominio no registrado / sin registro</span>');
  if (regMails.length) badges.push('<span class="b ok">Abuse del registrador encontrado</span>');
  else if (reg) badges.push('<span class="b warn">Sin email abuse del registrador</span>');
  badges.push(r.forms.some(f => f.scope === 'Registrador' && (f.url || f.links?.length)) ? '<span class="b ok">Registrador con formulario</span>' : '<span class="b bad">Registrador sin formulario</span>');
  if (r.forms.some(f => f.scope !== 'Registrador' && (f.url || f.links?.length))) badges.push('<span class="b ok">Hosting/CDN con formulario</span>');
  if (h.networks.some(n => n.abuse.emails.length)) badges.push('<span class="b ok">Abuse del hosting encontrado</span>');

  let html = `<div class="card"><h2>${esc(r.domain)}</h2><div class="sub">Zona .${esc(r.zone)}${r.country ? ' · ' + esc(r.country) : (r.generic ? ' · genérico' : '')}${reg ? ' · fuente: ' + esc(reg.source) : ''}</div><div class="badges">${badges.join('')}</div>`;
  html += whereBox(r);
  if (r.noDns) html += `<p><span class="b warn">Sin DNS: el dominio no resuelve</span> <span class="sub">Puede estar ya caído, suspendido o dado de baja. Si lo reportas, cita la URL y la fecha en que estaba activo; el histórico de DNS (abajo) ayuda a sacar el hosting anterior.</span></p>`;
  if (r.registryError) html += `<p><span class="b bad">${esc(r.registryError)}</span></p>`;
  if (r.noData) html += `<p class="sub">Este TLD no publica RDAP ni WHOIS accesible. Algunos ccTLD solo tienen consulta web en el registro oficial.</p>`;
  if (r.tldHint) html += `<p class="sub">${esc(r.tldHint.text)} ${link(r.tldHint.url, 'Abrir registro oficial')}</p>`;

  if (reg) {
    html += `<h3>Registrador (a quién reportar el dominio)</h3><div class="kv">
      <span>Registrador</span><span>${esc(reg.registrar) || '—'}${reg.ianaId ? ' (IANA ' + esc(reg.ianaId) + ')' : ''}</span>
      <span>Email abuse</span><span>${regMails.length ? regMails.map(mail).join('') : '<em>no publicado</em>'}</span>
      <span>Teléfono abuse</span><span>${(reg.abuse.phones || []).filter(Boolean).map(esc).join(', ') || '—'}</span>
      <span>Web registrador</span><span>${reg.registrarUrl ? link(reg.registrarUrl) : '—'}</span>
      <span>Creado / expira</span><span>${dt(reg.created)} / ${dt(reg.expires)}</span>
      <span>Estado</span><span>${esc((reg.status || []).join(', ')) || '—'}</span>
      ${reg.nameservers?.length ? `<span>Nameservers</span><span>${reg.nameservers.map(esc).join('<br>')}</span>` : ''}
    </div>`;
    if (!regMails.length && reg.otherEmails?.length) html += `<p class="sub">Otros emails vistos en el WHOIS (sin etiqueta abuse): ${reg.otherEmails.map(mail).join('')}</p>`;
  }

  html += `<h3>Hosting / red (a quién reportar el contenido)</h3>`;
  if (!h.networks.length) html += `<p class="sub">No se pudo resolver la IP del dominio.</p>`;
  for (const n of h.networks) {
    html += `<div class="kv">
      <span>IP</span><span>${esc(n.ip)} <small>${esc(n.range)}</small></span>
      <span>Red</span><span>${esc(n.name)} ${n.org ? '· ' + esc(n.org) : ''} ${n.country ? '· ' + esc(n.country) : ''}</span>
      <span>Email abuse</span><span>${n.abuse.emails.length ? n.abuse.emails.map(mail).join('') : '<em>no publicado</em>'}</span>
      ${n.abuse.phones.length ? `<span>Teléfono</span><span>${n.abuse.phones.map(esc).join(', ')}</span>` : ''}
    </div>`;
  }

  html += `<h3>Formularios de abuse</h3>`;
  if (!r.forms.length) html += `<p class="sub">No tengo ningún formulario para este registrador/hosting. Escribe al email abuse si lo hay.</p>`;
  for (const f of r.forms) {
    html += `<div class="form"><strong>${esc(f.name)}</strong> <span class="sub">· ${esc(f.scope)} · ${f.verified === 'conocido' ? 'lista propia' : 'detectado automáticamente'}</span>`;
    if (f.url) html += `<div>${link(f.url)}${f.alt ? ' · ' + link(f.alt, 'alternativo') : ''}</div>`;
    for (const l of f.links || []) html += `<div>${link(l.url, l.text || l.url)}</div>`;
    if (f.note) html += `<small>${esc(f.note)}</small>`;
    html += `</div>`;
  }

  if (reg?.raw) html += `<details><summary>Ver WHOIS en bruto</summary><pre>${esc(reg.raw)}</pre></details>`;
  return html + '</div>';
}

const STEPS = ['Consultando el registro del dominio…', 'Buscando el agente registrador…', 'Localizando el abuse y el hosting…', 'Comprobando formularios de reporte…'];
let stepTimer;
function loaderHtml(d) {
  clearInterval(stepTimer);
  let i = 0;
  stepTimer = setInterval(() => { const el = $('#lstep'); if (!el) return clearInterval(stepTimer); el.textContent = STEPS[++i % STEPS.length]; }, 2200);
  return `<div class="loader"><div class="lens"><svg viewBox="0 0 64 64" fill="none" stroke-width="5" stroke-linecap="round"><circle cx="27" cy="27" r="16"/><path d="m39 39 15 15"/></svg></div><h2>Buscando el abuse de ${esc(d)}</h2><p id="lstep">${STEPS[0]}</p><p class="sub">Puede tardar unos segundos</p></div>`;
}

function show(view) {
  $('#home').hidden = view !== 'home'; $('#res').hidden = view !== 'res';
  window.scrollTo(0, 0); document.documentElement.scrollTop = 0;
  if (view === 'home') $('#q').focus();
}
$('#back').addEventListener('click', () => { if (history.state?.v === 'res') history.back(); else show('home'); });
window.addEventListener('popstate', () => show(history.state?.v === 'res' ? 'res' : 'home'));
history.replaceState({ v: 'home' }, '');

$('#f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const list = [...new Set($('#q').value.split(/[\s,;]+/).map(s => s.trim()).filter(Boolean))].slice(0, 20);
  if (!list.length) return;
  $('#go').disabled = true; $('#out').innerHTML = ''; results = [];
  history.pushState({ v: 'res' }, ''); show('res');
  $('#out').innerHTML = loaderHtml(list[0]);
  for (let i = 0; i < list.length; i++) {
    $('#status').textContent = `Consultando ${i + 1}/${list.length}: ${list[i]}…`;
    let r;
    try { r = await (await fetch('/api/lookup?d=' + encodeURIComponent(list[i]))).json(); }
    catch { r = { input: list[i], error: 'Error de conexión con el servidor' }; }
    if (r.error && !r.input) r.input = list[i];
    results.push(r);
    if (i === 0) $('#out').innerHTML = '';
    $('#out').insertAdjacentHTML('beforeend', render(r));
  }
  clearInterval(stepTimer);
  $('#status').textContent = `Hecho (${list.length})`;
  $('#go').disabled = false;
});

document.addEventListener('click', (e) => {
  const es = e.target.closest('[data-es]');
  if (es) { navigator.clipboard.writeText(es.dataset.es).catch(() => {}); window.open('https://nic.es/sgnd/dominio/publicDetalleDominio.action', '_blank', 'noopener'); return; }
  const b = e.target.closest('[data-copy]');
  if (!b) return;
  navigator.clipboard.writeText(b.dataset.copy).then(() => { b.textContent = '¡Copiado!'; setTimeout(() => b.textContent = 'Copiar', 1200); });
});

const syncClr = () => { $('#clr').hidden = !$('#q').value; };
$('#q').addEventListener('input', syncClr);
$('#clr').addEventListener('click', () => { $('#q').value = ''; syncClr(); $('#q').focus(); });
