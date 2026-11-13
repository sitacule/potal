/*
 * 법인카드 Trace 연동 로그인(SSO) 중계 — Vercel 서버 함수 (외부 패키지 없음)
 *
 * 흐름: 포탈이 법인카드 Trace를 #sso=<포탈 ID 토큰> 으로 열면, 법인카드 Trace가 이 함수에 토큰을 보냄.
 *   1) 포탈 확인: 그 토큰으로 포탈 Firestore users/{uid} 문서를 읽음
 *      (Google이 토큰 서명·만료 검증, 포탈 규칙상 본인 문서만 읽힘) → status approved, 이메일 일치 확인
 *   2) 법인카드 Trace(Firebase card-e3cad)에서 같은 이메일 계정을 찾고(없으면 만듦)
 *   3) 그 계정용 1회 로그인 토큰(custom token)을 서비스 계정 키로 서명해 돌려줌
 *      → 법인카드 Trace가 signInWithCustomToken 으로 로그인 (기존 uid 그대로라 데이터 이전 없음)
 *
 * Vercel 환경변수(Settings → Environment Variables):
 *   CARD_SA_JSON  법인카드 Trace Firebase 프로젝트의 서비스 계정 키(JSON 파일 내용 전체)
 * 토큰·키는 로그에 남기지 않음.
 */
const crypto = require('crypto');

const PORTAL_PROJECT = 'potal-49183';
const ALLOWED_ORIGINS = ['https://sitacule.github.io'];
const ALLOWED_DOMAIN = '@lotte.net';
const FS_BASE = process.env.SSO_FIRESTORE_BASE || 'https://firestore.googleapis.com';          // 테스트용으로만 바꿈
const IDT_BASE = process.env.SSO_IDT_BASE || 'https://identitytoolkit.googleapis.com';
const OAUTH_URL = process.env.SSO_OAUTH_URL || 'https://oauth2.googleapis.com/token';

const b64url = b => Buffer.from(b).toString('base64url');
function signJwt(payload, key) {
  const head = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' })), body = b64url(JSON.stringify(payload));
  const sig = crypto.createSign('RSA-SHA256').update(head + '.' + body).sign(key).toString('base64url');
  return head + '.' + body + '.' + sig;
}
function payloadOf(t) {
  const p = String(t || '').split('.'); if (p.length !== 3) return null;
  try { return JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8')); } catch (e) { return null; }
}
async function fetchJson(url, opt) {
  const ac = new AbortController(), tm = setTimeout(() => ac.abort(), 8000);
  try { const r = await fetch(url, Object.assign({ signal: ac.signal }, opt)); let j = {}; try { j = await r.json(); } catch (e) { } return { ok: r.ok, status: r.status, j }; }
  finally { clearTimeout(tm); }
}

/* 1) 포탈 로그인 확인 → 이메일 */
async function verifyPortal(t) {
  const pl = payloadOf(t), now = Date.now() / 1000;
  if (!pl || pl.aud !== PORTAL_PROJECT || pl.iss !== 'https://securetoken.google.com/' + PORTAL_PROJECT || !(pl.exp > now) ||
      typeof pl.sub !== 'string' || !/^[A-Za-z0-9]{1,128}$/.test(pl.sub) || typeof pl.email !== 'string')
    return { code: 401, msg: '연동 정보가 올바르지 않거나 만료되었습니다. 포탈에서 다시 열어 주세요.' };
  const r = await fetchJson(FS_BASE + '/v1/projects/' + PORTAL_PROJECT + '/databases/(default)/documents/users/' + pl.sub,
    { headers: { authorization: 'Bearer ' + t } });
  if (!r.ok) return { code: 401, msg: '포탈 로그인을 확인하지 못했습니다. 포탈에서 다시 열어 주세요.' };
  const f = (r.j && r.j.fields) || {}, sv = k => String((f[k] && f[k].stringValue) || '').trim();
  const email = pl.email.trim().toLowerCase();
  if (sv('email').toLowerCase() !== email) return { code: 403, msg: '포탈 계정 정보가 맞지 않습니다.' };
  if (sv('status') !== 'approved') return { code: 403, msg: '포탈에서 승인되지 않은 계정입니다.' };
  if (!email.endsWith(ALLOWED_DOMAIN)) return { code: 403, msg: '회사 이메일(' + ALLOWED_DOMAIN + ') 계정만 사용할 수 있습니다.' };
  return { email };
}

/* 2) 법인카드 Trace 관리 API 접근 토큰 (서비스 계정) */
let cachedAccess = null;
async function accessToken(sa) {
  if (cachedAccess && cachedAccess.exp > Date.now() + 60e3) return cachedAccess.tok;
  const now = Math.floor(Date.now() / 1000);
  const assertion = signJwt({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/firebase',
    aud: OAUTH_URL, iat: now, exp: now + 3600 }, sa.private_key);
  const r = await fetchJson(OAUTH_URL, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + assertion });
  if (!r.ok || !r.j.access_token) throw new Error('oauth ' + r.status);
  cachedAccess = { tok: r.j.access_token, exp: Date.now() + (Number(r.j.expires_in) || 3600) * 1000 };
  return cachedAccess.tok;
}
async function cardUid(sa, email) {
  const at = await accessToken(sa), h = { authorization: 'Bearer ' + at, 'content-type': 'application/json' };
  const base = IDT_BASE + '/v1/projects/' + sa.project_id + '/accounts';
  const look = await fetchJson(base + ':lookup', { method: 'POST', headers: h, body: JSON.stringify({ email: [email] }) });
  if (!look.ok) throw new Error('lookup ' + look.status);
  const u = (look.j.users || [])[0];
  if (u) { if (u.disabled) return { disabled: true }; return { uid: u.localId }; }
  const made = await fetchJson(base, { method: 'POST', headers: h, body: JSON.stringify({ email, emailVerified: true }) });
  if (!made.ok || !made.j.localId) throw new Error('create ' + made.status);
  return { uid: made.j.localId, created: true };
}

/* 3) 1회 로그인 토큰 */
function customToken(sa, uid) {
  const now = Math.floor(Date.now() / 1000);
  return signJwt({ iss: sa.client_email, sub: sa.client_email,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now, exp: now + 3600, uid }, sa.private_key);
}

function readBody(req) {
  if (req.body && typeof req.body === 'object') return Promise.resolve(req.body);
  return new Promise(ok => { let s = ''; req.on('data', c => { s += c; if (s.length > 8192) req.destroy(); }); req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch (e) { ok({}); } }); req.on('error', () => ok({})); });
}

module.exports = async (req, res) => {
  const origin = req.headers.origin || '';
  const send = (code, o) => {
    res.statusCode = code;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('cache-control', 'no-store');
    if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('access-control-allow-origin', origin); res.setHeader('vary', 'Origin'); }
    res.end(JSON.stringify(o));
  };
  if (req.method === 'OPTIONS') {
    if (ALLOWED_ORIGINS.includes(origin)) { res.setHeader('access-control-allow-methods', 'POST'); res.setHeader('access-control-allow-headers', 'content-type'); res.setHeader('access-control-max-age', '3600'); }
    return send(204, {});
  }
  if (req.method !== 'POST') return send(405, { msg: 'POST만 허용됩니다.' });
  if (!ALLOWED_ORIGINS.includes(origin)) return send(403, { msg: '허용되지 않은 출처입니다.' });

  let sa;
  try { sa = JSON.parse(process.env.CARD_SA_JSON || ''); } catch (e) { sa = null; }
  if (!sa || !sa.client_email || !sa.private_key || !sa.project_id) return send(503, { msg: '연동 설정(서비스 계정 키)이 아직 준비되지 않았습니다. 관리자에게 문의하세요.' });

  const b = await readBody(req);
  try {
    const v = await verifyPortal(b.t);
    if (!v.email) return send(v.code, { msg: v.msg });
    const c = await cardUid(sa, v.email);
    if (c.disabled) return send(403, { msg: '법인카드 Trace에서 사용 중지된 계정입니다.' });
    console.log('card-sso ok', v.email, c.created ? '(new)' : '');
    return send(200, { token: customToken(sa, c.uid) });
  } catch (e) {
    console.log('card-sso error', String(e && e.message || e));
    return send(502, { msg: '연동 로그인 처리 중 오류가 났습니다. 잠시 뒤 다시 시도하세요.' });
  }
};
