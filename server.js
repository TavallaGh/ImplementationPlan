// Run with `node server.js` from this directory. Requires Node.js 18 or newer.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const directory = __dirname;
const envPath = path.join(directory, '.env');
const env = {};
for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match) env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, '$2');
}
for (const name of ['SUPABASE_URL', 'SUPABASE_KEY', 'ADMIN_USERNAME', 'ADMIN_PASSWORD']) {
    if (!env[name]) throw new Error(`Missing ${name} in .env`);
}
const baseUrl = new URL(env.SUPABASE_URL);
if (baseUrl.protocol !== 'https:' || baseUrl.username || baseUrl.password || baseUrl.search || baseUrl.hash) {
    throw new Error('SUPABASE_URL must be an HTTPS project URL');
}
const hostname = env.HOST || '127.0.0.1';
const port = Number(env.PORT || 3000);
const tables = new Set(['erp_deployment_stages', 'erp_deployment_people', 'erp_deployment_tasks', 'erp_deployment_dependencies']);
const sessions = new Map();
const attempts = new Map();
const sessionLifetime = 12 * 60 * 60 * 1000;

function send(res, status, data, extra = {}) {
    const body = JSON.stringify(data);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extra });
    res.end(body);
}
function readBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            if (body.length > 1024 * 1024) { reject(new Error('Request too large')); req.destroy(); }
        });
        req.on('end', () => resolve(body));
        req.on('error', reject);
    });
}
function sessionId(req) {
    return /(?:^|;\s*)erp_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1];
}
function isAdmin(req) {
    const id = sessionId(req);
    const expiry = id && sessions.get(id);
    if (expiry && expiry > Date.now()) return true;
    if (id) sessions.delete(id);
    return false;
}
function sameOrigin(req) {
    const origin = req.headers.origin;
    const host = req.headers.host;
    const site = req.headers['sec-fetch-site'];
    return site !== 'cross-site' && (!origin || origin === `http://${host}` || origin === `https://${host}`);
}
function equalSecret(a, b) {
    const left = crypto.createHash('sha256').update(String(a)).digest();
    const right = crypto.createHash('sha256').update(String(b)).digest();
    return crypto.timingSafeEqual(left, right);
}
const cookieOptions = 'Path=/; HttpOnly; SameSite=Strict' + (env.COOKIE_SECURE === 'true' ? '; Secure' : '');

const server = http.createServer(async (req, res) => {
    try {
        const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
        if (url.pathname === '/' || url.pathname === '/index.html') {
            if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { message: 'Method not allowed' });
            const html = fs.readFileSync(path.join(directory, 'index.html'));
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': html.length, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
            return res.end(req.method === 'HEAD' ? undefined : html);
        }
        if (url.pathname === '/api/auth/session' && req.method === 'GET') return send(res, 200, { isAdmin: isAdmin(req) });
        if (url.pathname === '/api/auth/login' && req.method === 'POST') {
            if (!sameOrigin(req)) return send(res, 403, { message: 'Forbidden' });
            const ip = req.socket.remoteAddress;
            const record = attempts.get(ip) || { count: 0, until: 0 };
            if (record.until > Date.now()) return send(res, 429, { message: 'Too many attempts' });
            let credentials;
            try { credentials = JSON.parse(await readBody(req)); } catch { return send(res, 400, { message: 'Invalid request' }); }
            if (typeof credentials.username !== 'string' || typeof credentials.password !== 'string' ||
                !equalSecret(credentials.username, env.ADMIN_USERNAME) || !equalSecret(credentials.password, env.ADMIN_PASSWORD)) {
                record.count++;
                if (record.count >= 5) { record.until = Date.now() + 15 * 60 * 1000; record.count = 0; }
                attempts.set(ip, record);
                return send(res, 401, { message: 'Invalid credentials' });
            }
            attempts.delete(ip);
            const id = crypto.randomBytes(32).toString('hex');
            sessions.set(id, Date.now() + sessionLifetime);
            return send(res, 200, { isAdmin: true }, { 'Set-Cookie': `erp_session=${id}; Max-Age=43200; ${cookieOptions}` });
        }
        if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
            if (!sameOrigin(req)) return send(res, 403, { message: 'Forbidden' });
            sessions.delete(sessionId(req));
            return send(res, 200, { isAdmin: false }, { 'Set-Cookie': `erp_session=; Max-Age=0; ${cookieOptions}` });
        }
        const table = url.pathname.startsWith('/api/db/') ? url.pathname.slice('/api/db/'.length) : '';
        if (!tables.has(table)) return send(res, 404, { message: 'Not found' });
        if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(req.method)) return send(res, 405, { message: 'Method not allowed' });
        if (req.method !== 'GET' && (!isAdmin(req) || !sameOrigin(req))) return send(res, 403, { message: 'Admin login required' });
        if (url.search.length > 4096) return send(res, 400, { message: 'Query too long' });
        const upstream = new URL(`/rest/v1/${table}${url.search}`, baseUrl);
        const headers = { apikey: env.SUPABASE_KEY, Accept: 'application/json' };
        if (env.SUPABASE_KEY.startsWith('eyJ')) headers.Authorization = `Bearer ${env.SUPABASE_KEY}`;
        if (req.headers.range && /^\d+-\d+$/.test(req.headers.range)) headers.Range = req.headers.range;
        if (req.headers.prefer && /^(return=representation|resolution=merge-duplicates,missing=default,return=representation)$/.test(req.headers.prefer)) headers.Prefer = req.headers.prefer;
        let body;
        if (req.method !== 'GET' && req.method !== 'DELETE') {
            body = await readBody(req);
            JSON.parse(body);
            headers['Content-Type'] = 'application/json';
        }
        const response = await fetch(upstream, { method: req.method, headers, body, signal: AbortSignal.timeout(15000) });
        const result = await response.text();
        res.writeHead(response.status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
        return res.end(result);
    } catch (error) {
        console.error(error);
        if (!res.headersSent && !res.destroyed) send(res, 502, { message: 'Server or database request failed' });
    }
});
server.listen(port, hostname, () => console.log(`ERP app: http://${hostname}:${port}`));
