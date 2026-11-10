// Idea y desarrollo: Yaiza Rios (Cyberzaintza). Todos los derechos reservados.
// Buscador de abuse de dominios (cualquier TLD). Sin dependencias: Node 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;

const PORT = process.env.PORT || 3000;
const UA = 'Mozilla/5.0 (compatible; AbuseFinder/1.0)';

// ---------- utilidades ----------
const sleepTimeout = (ms) => AbortSignal.timeout(ms);
const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const uniq = (a) => [...new Set(a.filter(Boolean))];

function validDomain(d) {
  return /^(?=.{3,253}$)([a-z0-9¡-￿]([a-z0-9¡-￿-]{0,61}[a-z0-9¡-￿])?\.)+[a-z¡-￿0-9-]{2,63}$/i.test(d);
}

function cleanInput(raw, keepWww) {
  let d = String(raw || '').trim().toLowerCase();
  d = d.replace(/hxxp/g, 'http').replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/g, '.').replace(/\s+/g, '');
  d = d.replace(/^[a-z]+:\/\//, '').replace(/^.*@/, '');
  d = d.split(/[\/?#:]/)[0].replace(/\.$/, '');
  if (!keepWww) d = d.replace(/^www\./, '');
  try { d = require('url').domainToASCII(d) || d; } catch {}
  return d;
}

function safePublicUrl(u) {
  try {
    const x = new URL(u);
    if (x.protocol !== 'https:' && x.protocol !== 'http:') return null;
    if (/^(localhost|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[)/i.test(x.hostname)) return null;
    if (!x.hostname.includes('.')) return null;
    return x.href;
  } catch { return null; }
}

// ---------- RDAP ----------
let bootstrap = { at: 0, map: null };
async function getBootstrap() {
  if (bootstrap.map && Date.now() - bootstrap.at < 864e5) return bootstrap.map;
  const r = await fetch('https://data.iana.org/rdap/dns.json', { signal: sleepTimeout(10000) });
  const j = await r.json();
  const map = {};
  for (const [tlds, urls] of j.services) for (const t of tlds) map[t.toLowerCase()] = urls.find(u => u.startsWith('https')) || urls[0];
  bootstrap = { at: Date.now(), map };
  return map;
}

async function rdapGet(url) {
  const r = await fetch(url, { headers: { accept: 'application/rdap+json, application/json', 'user-agent': UA }, signal: sleepTimeout(12000), redirect: 'follow' });
  if (r.status === 404) return { notFound: true };
  if (!r.ok) throw new Error('RDAP HTTP ' + r.status);
  return r.json();
}

const vget = (ent, key) => {
  const arr = ent?.vcardArray?.[1] || [];
  const out = [];
  for (const it of arr) if (it[0] === key) out.push(typeof it[3] === 'string' ? it[3] : (Array.isArray(it[3]) ? it[3].filter(Boolean).join(' ') : ''));
  return out;
};
const fn = (ent) => vget(ent, 'fn')[0] || vget(ent, 'org')[0] || '';

function walkEntities(obj, cb, depth = 0) {
  for (const e of obj?.entities || []) { cb(e, depth); walkEntities(e, cb, depth + 1); }
}

function abuseFromEntities(obj) {
  const emails = [], phones = [], names = [];
  walkEntities(obj, (e) => {
    if ((e.roles || []).includes('abuse')) {
      emails.push(...vget(e, 'email')); phones.push(...vget(e, 'tel').map(t => t.replace(/^tel:/, '')));
      names.push(fn(e));
    }
  });
  return { emails: uniq(emails), phones: uniq(phones), names: uniq(names) };
}

function parseDomainRdap(j) {
  const reg = (j.entities || []).find(e => (e.roles || []).includes('registrar'));
  const ev = (a) => (j.events || []).find(e => e.eventAction === a)?.eventDate;
  const abuse = abuseFromEntities(j);
  let registrarUrl = null;
  if (reg) {
    const l = (reg.links || []).find(l => l.rel === 'about' || l.rel === 'related' || l.rel === 'self');
    registrarUrl = l?.href || null;
    const pid = (reg.publicIds || []).map(p => p.identifier);
    registrarUrl = registrarUrl && !/rdap/i.test(registrarUrl) ? registrarUrl : null;
    var ianaId = pid[0];
  }
  const relatedRdap = (j.links || []).find(l => l.rel === 'related' && /rdap|application\/rdap/i.test((l.type || '') + l.href))?.href;
  return {
    registrar: reg ? fn(reg) : '',
    registrarUrl,
    ianaId: typeof ianaId === 'string' ? ianaId : '',
    abuse,
    status: j.status || [],
    created: ev('registration'), expires: ev('expiration'), updated: ev('last changed'),
    nameservers: (j.nameservers || []).map(n => (n.ldhName || '').toLowerCase()).filter(Boolean),
    relatedRdap,
  };
}

async function rdapDomain(domain) {
  const map = await getBootstrap();
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];
  const base = map[tld];
  if (!base) return { noRdap: true };
  // prueba dominio completo y va quitando subdominios (a.b.co.uk -> b.co.uk -> co.uk)
  for (let i = 0; i <= labels.length - 2; i++) {
    const cand = labels.slice(i).join('.');
    const j = await rdapGet(base.replace(/\/?$/, '/') + 'domain/' + cand);
    if (j.notFound) continue;
    const info = parseDomainRdap(j);
    info.queried = cand;
    // registros "thin" (.com): el abuse está en el RDAP del registrador
    if (!info.abuse.emails.length && info.relatedRdap && safePublicUrl(info.relatedRdap)) {
      try {
        const j2 = await rdapGet(info.relatedRdap);
        if (!j2.notFound) {
          const i2 = parseDomainRdap(j2);
          if (i2.abuse.emails.length || i2.abuse.phones.length) info.abuse = i2.abuse;
          info.registrar = info.registrar || i2.registrar;
          info.registrarUrl = info.registrarUrl || i2.registrarUrl;
        }
      } catch {}
    }
    info.source = 'RDAP';
    return info;
  }
  return { notFoundRdap: true };
}

// ---------- WHOIS (respaldo para TLD sin RDAP) ----------
function whoisQuery(server, query, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const s = net.connect(43, server);
    let data = '';
    s.setTimeout(timeout, () => { s.destroy(); reject(new Error('timeout whois ' + server)); });
    s.on('connect', () => s.write(query + '\r\n'));
    s.on('data', (c) => { data += c; if (data.length > 200000) s.destroy(); });
    s.on('end', () => resolve(data));
    s.on('close', () => resolve(data));
    s.on('error', reject);
  });
}

async function whoisDomain(domain) {
  const labels = domain.split('.');
  const tld = labels[labels.length - 1];
  const iana = await whoisQuery('whois.iana.org', tld);
  const server = (iana.match(/^whois:\s*(\S+)/im) || [])[1];
  if (!server) return null;
  const noData = (t) => /no data found|no match|not found|no entries found|status:s*free|is free|available/i.test(t) && !/registrar/i.test(t);
  let text = '', found = domain;
  // prueba el dominio y va quitando subdominios (a.b.vu -> b.vu) hasta que el registro lo reconozca
  for (let i = 0; i <= labels.length - 2; i++) {
    const cand = labels.slice(i).join('.');
    let q = cand;
    if (server === 'whois.denic.de') q = '-T dn,ace ' + cand;
    if (server === 'whois.jprs.jp') q = cand + '/e';
    text = await whoisQuery(server, q);
    found = cand;
    if (!noData(text)) break;
  }
  // referencia a otro whois (registros thin)
  const ref = (text.match(/Registrar WHOIS Server:\s*(\S+)/i) || [])[1];
  if (ref && ref.toLowerCase() !== server) {
    try { const t2 = await whoisQuery(ref.replace(/^whois:\/\//, ''), domain); if (t2.length > 100) text += '\n\n' + t2; } catch {}
  }
  const line = (re) => (text.match(re) || [])[1]?.trim() || '';
  const abuseEmails = [];
  for (const l of text.split(/\r?\n/)) if (/abuse/i.test(l)) abuseEmails.push(...(l.match(EMAIL_RE) || []));
  const allEmails = uniq(text.match(EMAIL_RE) || []).filter(e => !/^(noc|domain-?admin)@(registro|nic)/i.test(e));
  return {
    source: 'WHOIS (' + server + ')', whoisServer: server, queried: found,
    registrar: line(/^\s*(?:Registrar|Sponsoring Registrar|Registrar Name)\s*:\s*(.+)$/im) || line(/^\s*\[Registrar\]\s*(.+)$/im) || line(/^\s*\[Name\]\s*(.+)$/im),
    ianaId: line(/Registrar IANA ID:\s*(\d+)/i),
    registrarUrl: line(/Registrar URL:\s*(\S+)/i),
    abuse: {
      emails: uniq(abuseEmails.map(e => e.toLowerCase())),
      phones: uniq([line(/Registrar Abuse Contact Phone:\s*(.+)/i)]),
      names: [],
    },
    otherEmails: allEmails.map(e => e.toLowerCase()).filter(e => !abuseEmails.map(a => a.toLowerCase()).includes(e)).slice(0, 6),
    created: line(/(?:Creation Date|Registered on|Registration Time|Created|\[Registered Date\]|\[登録年月日\])\s*:?\s*(.+)/i),
    expires: line(/(?:Expir\w+ Date|Expiry date|Registry Expiry Date|\[Expires on\])\s*:?\s*(.+)/i),
    status: [],
    nameservers: uniq((text.match(/^\s*(?:Name Server|Nserver|\[Name Server\])\s*:?\s*(\S+)/gim) || []).map(l => l.replace(/^\s*[^:\]]*[:\]]\s*/, '').toLowerCase())),
    raw: text.slice(0, 6000),
    notFound: /no match|not found|no entries found|status:\s*free|available/i.test(text) && !/registrar/i.test(text),
  };
}

// ---------- hosting (IP -> RDAP) ----------
const resolver = new dns.Resolver({ timeout: 3000, tries: 1 });
try { resolver.setServers([...new Set([...require('dns').getServers(), '1.1.1.1', '8.8.8.8'])]); } catch {}
const dnsTry = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('dns timeout')), 7000))]).catch(() => []);

async function hostingInfo(domain, hostHint) {
  const out = { ips: [], nameservers: [], networks: [], geo: null };
  const ns = await dnsTry(resolver.resolveNs(domain));
  out.nameservers = ns.map(s => s.toLowerCase());
  // el dominio sin "www" a veces no tiene IP (p. ej. .go.jp): prueba el host pedido, el dominio y www.
  const cands = [...new Set([hostHint, domain, 'www.' + domain].filter(Boolean))];
  for (const h of cands) {
    const [a4, a6] = await Promise.all([dnsTry(resolver.resolve4(h)), dnsTry(resolver.resolve6(h))]);
    out.ips = [...a4, ...a6.slice(0, 1)].slice(0, 3);
    if (out.ips.length) { out.host = h; break; }
  }
  const seen = new Set();
  for (const ip of out.ips) {
    try {
      const j = await rdapGet('https://rdap.org/ip/' + ip);
      if (j.notFound) continue;
      const key = j.handle || j.name;
      if (seen.has(key)) continue; seen.add(key);
      const abuse = abuseFromEntities(j);
      const org = (j.entities || []).map(fn).filter(Boolean)[0] || '';
      out.networks.push({ ip, name: j.name || '', handle: j.handle || '', country: j.country || '', org, range: [j.startAddress, j.endAddress].filter(Boolean).join(' – '), abuse });
    } catch {}
  }
  return out;
}

// ---------- formularios de abuse ----------
const KNOWN_FORMS = [
  { re: /cloudflare/i, name: 'Cloudflare', url: 'https://www.cloudflare.com/trust-hub/reporting-abuse/', note: 'Cloudflare solo hace de proxy: el formulario reenvía al hosting real. Para pedir la IP real usa el tipo de abuso correcto del formulario.' },
  { re: /godaddy|wild ?west|domains by proxy/i, name: 'GoDaddy', url: 'https://supportcenter.godaddy.com/abuse' },
  { re: /namecheap/i, name: 'Namecheap', url: 'https://www.namecheap.com/support/knowledgebase/article.aspx/9622/' , alt: 'https://www.namecheap.com/legal/general/abuse-contact/' },
  { re: /tucows|hover|enom/i, name: 'Tucows / eNom', url: 'https://tucowsdomains.com/abuse-form/' },
  { re: /google/i, name: 'Google', url: 'https://support.google.com/legal/troubleshooter/1114905', alt: 'https://support.google.com/code/contact/cloud_platform_report' },
  { re: /squarespace/i, name: 'Squarespace Domains', url: 'https://support.squarespace.com/hc/en-us/requests/new' },
  { re: /fastly/i, name: 'Fastly', url: 'https://www.fastly.com/abuse' },
  { re: /markmonitor/i, name: 'MarkMonitor', url: 'https://www.markmonitor.com/contact/abuse' },
  { re: /hostinger/i, name: 'Hostinger', url: 'https://www.hostinger.com/report-abuse' },
  { re: /ionos|1&1|1and1/i, name: 'IONOS', url: 'https://www.ionos.com/help/abuse/' },
  { re: /ovh/i, name: 'OVHcloud', url: 'https://report.abuse.ovh.com/' },
  { re: /hetzner/i, name: 'Hetzner', url: 'https://abuse.hetzner.com/' },
  { re: /digitalocean/i, name: 'DigitalOcean', url: 'https://www.digitalocean.com/company/contact/abuse' },
  { re: /amazon|aws/i, name: 'Amazon AWS', url: 'https://support.aws.amazon.com/#/contacts/report-abuse' },
  { re: /microsoft|azure/i, name: 'Microsoft', url: 'https://msrc.microsoft.com/report/abuse' },
  { re: /porkbun/i, name: 'Porkbun', url: 'https://porkbun.com/abuse' },
  { re: /name\.com/i, name: 'Name.com', url: 'https://www.name.com/support/articles/abuse' },
  { re: /dynadot/i, name: 'Dynadot', url: 'https://www.dynadot.com/about/report-abuse' },
  { re: /gname/i, name: 'GName', url: 'https://www.gname.com/abuse' },
  { re: /alibaba|hichina|aliyun|net\.cn|万网/i, name: 'Alibaba Cloud', url: 'https://report.aliyun.com/' },
  { re: /tencent|dnspod/i, name: 'Tencent Cloud', url: 'https://console.cloud.tencent.com/workorder/category' },
  { re: /gandi/i, name: 'Gandi', url: 'https://www.gandi.net/en/contact/abuse' },
  { re: /ovh|scaleway|online\.net/i, name: 'Scaleway', url: 'https://www.scaleway.com/en/abuse/' },
  { re: /linode|akamai/i, name: 'Akamai / Linode', url: 'https://www.linode.com/contact/abuse/' },
  { re: /vultr|choopa/i, name: 'Vultr', url: 'https://www.vultr.com/company/contact/abuse/' },
  { re: /contabo/i, name: 'Contabo', url: 'https://contabo.com/en/abuse/' },
  { re: /reg\.ru|regru/i, name: 'REG.RU', url: 'https://www.reg.ru/support/abuse/' },
  { re: /namesilo/i, name: 'NameSilo', url: 'https://www.namesilo.com/report_abuse' },
  { re: /sav\.com/i, name: 'Sav.com', url: 'https://www.sav.com/abuse/' },
  { re: /register\.it|aruba/i, name: 'Aruba / Register.it', url: 'https://www.aruba.it/en/abuse.aspx' },
  { re: /strato/i, name: 'STRATO', url: 'https://www.strato.de/faq/article/2078/' },
  { re: /one\.com/i, name: 'one.com', url: 'https://www.one.com/en/contact/abuse' },
  { re: /wix/i, name: 'Wix', url: 'https://www.wix.com/abuse' },
  { re: /shopify/i, name: 'Shopify', url: 'https://www.shopify.com/legal/report-abuse' },
  { re: /pdr ltd|publicdomainregistry|endurance|bluehost|hostgator/i, name: 'PDR / Endurance', url: 'https://www.publicdomainregistry.com/process-for-abuse-complaint/' },
];

async function detectFormLinks(url) {
  const safe = safePublicUrl(url);
  if (!safe) return [];
  try {
    const r = await fetch(safe, { headers: { 'user-agent': UA, accept: 'text/html' }, signal: sleepTimeout(6000), redirect: 'follow' });
    if (!r.ok) return [];
    const html = (await r.text()).slice(0, 1500000);
    const base = r.url;
    const found = [];
    const re = /<a\b[^>]*?href\s*=\s*["']([^"'#]+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = re.exec(html)) && found.length < 6) {
      const text = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      if (/abuse|report (a |an )?(abuse|violation|phishing)|denunci|abus|missbrauch/i.test(text + ' ' + m[1])) {
        try { const abs = new URL(m[1], base).href; if (safePublicUrl(abs)) found.push({ url: abs, text: text.slice(0, 80) }); } catch {}
      }
    }
    const seen = new Set();
    return found.filter(f => !seen.has(f.url) && seen.add(f.url)).slice(0, 4);
  } catch { return []; }
}

function knownForm(...texts) {
  const s = texts.filter(Boolean).join(' | ');
  return KNOWN_FORMS.find(k => k.re.test(s)) || null;
}

const TLD_HINTS = {
  de: { text: '.de: DENIC no da por WHOIS el titular ni el abuse. Hay que consultarlo en su WHOIS web (captcha) o reportar al hosting.', url: 'https://webwhois.denic.de/?lang=en' },
  es: { text: '.es no publica RDAP ni WHOIS por red. Consulta manual en Red.es (necesita captcha) y reporta al hosting/IP de abajo.', url: 'https://nic.es/sgnd/dominio/publicDetalleDominio.action' },
  fr: { text: '.fr: usa el WHOIS web de AFNIC.', url: 'https://www.afnic.fr/en/domain-names-and-support/everything-about-domain-names/find-a-domain-name-or-a-holder-whois/' },
  cn: { text: '.cn: consulta en CNNIC.', url: 'https://whois.cnnic.cn/' },
};

const SLD = new Set(['com','co','org','net','nom','gob','gov','edu','ac','or','ne','go','gouv','asso','ltd','plc','sch','mil','info','biz']);
function zoneInfo(domain) {
  const l = domain.split('.');
  const tld = l[l.length - 1];
  let zone = tld;
  if (l.length >= 3 && tld.length === 2 && SLD.has(l[l.length - 2])) zone = l[l.length - 2] + '.' + tld;
  let country = '';
  if (tld.length === 2) {
    const code = tld === 'uk' ? 'GB' : tld.toUpperCase();
    try { country = new Intl.DisplayNames(['es'], { type: 'region' }).of(code); if (country === code) country = ''; } catch {}
  }
  return { zone, country, generic: tld.length > 2 };
}

// ---------- consulta completa ----------
async function lookup(inputRaw) {
  const domain = cleanInput(inputRaw);
  const hostHint = cleanInput(inputRaw, true);
  if (!validDomain(domain)) return { input: inputRaw, error: 'Dominio no válido' };
  const res = { input: inputRaw, domain, tld: domain.split('.').pop(), ...zoneInfo(domain) };

  const [reg, host] = await Promise.all([
    (async () => {
      try {
        const r = await rdapDomain(domain);
        if (r && !r.noRdap && !r.notFoundRdap) return r;
        const w = await whoisDomain(domain).catch(() => null);
        if (w) return w;
        return r?.notFoundRdap ? { notRegistered: true } : { noData: true };
      } catch (e) {
        const w = await whoisDomain(domain).catch(() => null);
        return w || { error: 'No se pudo consultar el registro: ' + e.message };
      }
    })(),
    hostingInfo(domain, hostHint),
  ]);

  if (reg.error) res.registryError = reg.error;
  if (reg.notRegistered) res.notRegistered = true;
  if (reg.noData) res.noData = true;
  res.registry = reg.error || reg.notRegistered || reg.noData ? null : reg;
  res.hosting = host;
  res.noDns = !host.ips.length && !host.nameservers.length;
  if (res.noData || (res.registry && !res.registry.abuse.emails.length)) res.tldHint = TLD_HINTS[res.tld] || null;

  // formularios
  const forms = [];
  const regKnown = res.registry && knownForm(res.registry.registrar, res.registry.registrarUrl);
  if (regKnown) forms.push({ scope: 'Registrador', name: regKnown.name, url: regKnown.url, alt: regKnown.alt, note: regKnown.note, verified: 'conocido' });
  const cfByNs = host.nameservers.some(n => /cloudflare\.com$/.test(n));
  const seenForm = new Set(forms.map(f => f.name));
  if (cfByNs && !seenForm.has('Cloudflare')) { const k = KNOWN_FORMS[0]; forms.push({ scope: 'Proxy / DNS', name: k.name, url: k.url, note: k.note, verified: 'conocido' }); seenForm.add('Cloudflare'); }
  for (const n of host.networks) {
    const k = knownForm(n.org, n.name);
    if (k && !seenForm.has(k.name)) { forms.push({ scope: 'Hosting (IP ' + n.ip + ')', name: k.name, url: k.url, alt: k.alt, note: k.note, verified: 'conocido' }); seenForm.add(k.name); }
  }
  // detección automática en la web del registrador / hosting
  const urls = [];
  if (res.registry?.registrarUrl) urls.push(['Registrador', res.registry.registrarUrl]);
  const detected = await Promise.all(urls.map(async ([scope, u]) => ({ scope, links: await detectFormLinks(u), u })));
  for (const d of detected) if (d.links.length) forms.push({ scope: d.scope, name: 'Enlaces "abuse" encontrados en ' + new URL(d.u).hostname, links: d.links, verified: 'detectado' });
  res.forms = forms;
  res.hasForm = forms.some(f => f.url || (f.links && f.links.length));

  return res;
}

// ---------- servidor ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const cache = new Map();
const hits = new Map();

http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://x');
  if (u.pathname === '/api/lookup') {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter(t => now - t < 60000);
    arr.push(now); hits.set(ip, arr);
    res.setHeader('content-type', 'application/json; charset=utf-8');
    if (arr.length > 40) { res.statusCode = 429; return res.end(JSON.stringify({ error: 'Demasiadas consultas, espera un minuto' })); }
    const d = cleanInput(u.searchParams.get('d'), true);
    const c = cache.get(d);
    if (c && now - c.at < 600000) return res.end(JSON.stringify(c.data));
    try {
      const data = await lookup(u.searchParams.get('d'));
      if (!data.error) cache.set(d, { at: now, data });
      return res.end(JSON.stringify(data));
    } catch (e) {
      res.statusCode = 500; return res.end(JSON.stringify({ error: e.message }));
    }
  }
  let f = u.pathname === '/' ? '/index.html' : decodeURIComponent(u.pathname);
  f = path.normalize(f).replace(/^(\.\.[\/\\])+/, '');
  const file = path.join(__dirname, 'public', f);
  if (!file.startsWith(path.join(__dirname, 'public'))) { res.statusCode = 403; return res.end(); }
  fs.readFile(file, (err, buf) => {
    if (err) { res.statusCode = 404; return res.end('No encontrado'); }
    res.setHeader('content-type', MIME[path.extname(file)] || 'application/octet-stream');
    res.end(buf);
  });
}).listen(PORT, () => console.log('Abuse finder en http://localhost:' + PORT));
