import express from 'express'; import helmet from 'helmet'; import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser'; import bcrypt from 'bcryptjs'; import { z } from 'zod';
import nacl from 'tweetnacl'; import bs58 from 'bs58'; import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite'; import { createRequire } from 'node:module'; const { PublicKey, Connection, TransactionInstruction, TransactionMessage, VersionedTransaction } = createRequire(import.meta.url)('@solana/web3.js');
import { USDC, STOCKS, BY_MINT } from './tokens.js';

const PORT = process.env.PORT || 3000, PROD = process.env.NODE_ENV === 'production';
const FEE_WALLET = process.env.FEE_WALLET || ''; // Seven must set this
const FEE_BPS = 100; const RPC = process.env.SOLANA_RPC || 'https://api.mainnet-beta.solana.com';
const JUP = process.env.JUP_API_KEY ? 'https://api.jup.ag' : 'https://lite-api.jup.ag'; // free lite tier is rate limited
const JH = process.env.JUP_API_KEY ? { 'x-api-key': process.env.JUP_API_KEY } : {};
async function jfetch(url, opt = {}) { for (let t = 0; ; t++) { // retry 429s and transient errors with backoff
  const r = await fetch(url, { ...opt, headers: { ...(opt.headers||{}), ...JH } }); const j = await r.json().catch(() => ({}));
  if (r.ok && !j.error) return j;
  if (t >= 4 || (r.status < 500 && r.status !== 429)) throw new Error(r.status === 429 ? 'Price service busy, try again' : (j.error || 'Swap service error'));
  await new Promise(s => setTimeout(s, 400 * 2 ** t)); } }
const db = new DatabaseSync(process.env.DB_PATH || './data.db');
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, pw TEXT NOT NULL, wallet TEXT UNIQUE, not_us INTEGER NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces(user_id INTEGER PRIMARY KEY, nonce TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS swaps(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, sig TEXT UNIQUE NOT NULL, side TEXT, symbol TEXT, in_mint TEXT, out_mint TEXT, in_amt REAL, out_amt REAL, usd REAL, fee_usd REAL, ts INTEGER);
CREATE TABLE IF NOT EXISTS watch(user_id INTEGER, mint TEXT, PRIMARY KEY(user_id,mint));`);

const app = express(); app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc:["'self'"], scriptSrc:["'self'"], styleSrc:["'self'"], imgSrc:["'self'",'data:','https://xstocks-metadata.backed.fi'],
  connectSrc:["'self'"], frameAncestors:["'none'"], objectSrc:["'none'"], baseUri:["'self'"], formAction:["'self'"] } } }));
app.use(express.json({ limit: '20kb' })); app.use(cookieParser());
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 120 }));
const authLimit = rateLimit({ windowMs: 15*60_000, limit: 20, message: { error: 'Too many attempts, try later' } });

const hash = s => crypto.createHash('sha256').update(s).digest('hex');
function newSession(res, uid) {
  const tok = crypto.randomBytes(32).toString('hex'), csrf = crypto.randomBytes(24).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run(hash(tok), uid, csrf, Date.now()+7*864e5);
  res.cookie('sid', tok, { httpOnly:true, secure:PROD, sameSite:'strict', maxAge:7*864e5, path:'/' });
  return csrf;
}
function auth(req, res, next) {
  const s = req.cookies.sid && db.prepare('SELECT * FROM sessions WHERE token=? AND expires>?').get(hash(req.cookies.sid), Date.now());
  if (!s) return res.status(401).json({ error: 'Not logged in' });
  if (req.method !== 'GET' && req.get('x-csrf-token') !== s.csrf) return res.status(403).json({ error: 'Bad CSRF token' });
  req.user = db.prepare('SELECT id,email,wallet FROM users WHERE id=?').get(s.user_id); req.csrf = s.csrf; next();
}
const bad = (res, e) => res.status(400).json({ error: e });
const creds = z.object({ email: z.string().email().max(200).transform(s=>s.toLowerCase().trim()), password: z.string().min(10).max(200) });

app.post('/api/signup', authLimit, async (req, res) => {
  const inv = typeof req.body?.invite === 'string' ? req.body.invite : '', OWNER = process.env.OWNER_INVITE_CODE || '';
  const owner = OWNER.length >= 16 && inv.length === OWNER.length && crypto.timingSafeEqual(Buffer.from(inv), Buffer.from(OWNER));
  if (inv && !owner) return bad(res, 'That invite code is not valid. Remove it or check the link.');
  const p = creds.extend({ notUS: z.boolean().optional(), invite: z.string().max(200).optional() }).safeParse(req.body);
  if (!p.success) { const f = p.error.issues[0]?.path?.[0]; return bad(res, f === 'email' ? 'Enter a valid email address.' : f === 'password' ? 'Password must be at least 10 characters.' : 'Check your details and try again.'); }
  if (!owner && p.data.notUS !== true) return bad(res, 'Please confirm you are not a US person to continue.');
  if (!owner && (req.get('cf-ipcountry') === 'US' || req.get('x-vercel-ip-country') === 'US')) return res.status(451).json({ error: 'Sorry, StockChain is not available in the US.' });
  try { const r = db.prepare('INSERT INTO users(email,pw,not_us,created) VALUES(?,?,1,?)').run(p.data.email, await bcrypt.hash(p.data.password, 12), Date.now());
    res.json({ csrf: newSession(res, Number(r.lastInsertRowid)) });
  } catch { bad(res, 'An account with that email may already exist. Try logging in.'); }
});
app.post('/api/login', authLimit, async (req, res) => {
  const p = creds.safeParse(req.body); if (!p.success) return bad(res, 'Invalid email or password');
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(p.data.email);
  const ok = await bcrypt.compare(p.data.password, u?.pw || '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv');
  if (!u || !ok) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ csrf: newSession(res, u.id) });
});
app.post('/api/logout', auth, (req, res) => { db.prepare('DELETE FROM sessions WHERE token=?').run(hash(req.cookies.sid)); res.clearCookie('sid'); res.json({ ok:true }); });
app.get('/api/me', auth, (req, res) => res.json({ ...req.user, csrf: req.csrf, feeConfigured: !!FEE_WALLET }));

// Wallet link: Sign-In-With-Solana style message + nonce
const linkMsg = (u, n) => `${process.env.APP_DOMAIN || 'localhost'} wants you to link your Solana wallet to account ${u.email}.\n\nNonce: ${n}\nThis does not cost anything or move funds.`;
app.post('/api/wallet/nonce', auth, (req, res) => {
  const n = crypto.randomBytes(16).toString('hex');
  db.prepare('INSERT OR REPLACE INTO nonces VALUES(?,?,?)').run(req.user.id, n, Date.now()+5*60_000);
  res.json({ message: linkMsg(req.user, n) });
});
app.post('/api/wallet/verify', auth, (req, res) => {
  const p = z.object({ address: z.string().min(32).max(44), signature: z.string().max(200) }).safeParse(req.body); if (!p.success) return bad(res, 'Bad input');
  const n = db.prepare('SELECT * FROM nonces WHERE user_id=? AND expires>?').get(req.user.id, Date.now()); if (!n) return bad(res, 'Nonce expired');
  db.prepare('DELETE FROM nonces WHERE user_id=?').run(req.user.id);
  try { const ok = nacl.sign.detached.verify(new TextEncoder().encode(linkMsg(req.user, n.nonce)), bs58.decode(p.data.signature), new PublicKey(p.data.address).toBytes());
    if (!ok) return bad(res, 'Signature invalid');
    db.prepare('UPDATE users SET wallet=? WHERE id=?').run(p.data.address, req.user.id); res.json({ wallet: p.data.address });
  } catch { bad(res, 'Wallet already linked to another account or invalid'); }
});

// Markets
let priceCache = { t:0, d:{} };
async function prices() {
  if (Date.now() - priceCache.t < 15_000) return priceCache.d;
  const j = await jfetch(`${JUP}/price/v3?ids=${[USDC,...STOCKS].map(t=>t.mint).join(',')}`);
  priceCache = { t: Date.now(), d: j }; return j;
}
app.get('/api/tokens', async (req, res) => {
  const p = await prices().catch(()=>({}));
  res.json(STOCKS.map(t => ({ ...t, price: p[t.mint]?.usdPrice ?? null, change24h: p[t.mint]?.priceChange24h ?? null })));
});

// Portfolio (reads chain, never custody)
async function rpc(method, params) { const r = await fetch(RPC, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ jsonrpc:'2.0', id:1, method, params }) }); const j = await r.json(); if (j.error) throw new Error(j.error.message); return j.result; }
app.get('/api/portfolio', auth, async (req, res) => {
  if (!req.user.wallet) return bad(res, 'Link a wallet first');
  const bal = {};
  try { for (const prog of [USDC.program, STOCKS[0].program]) {
    const r = await rpc('getTokenAccountsByOwner', [req.user.wallet, { programId: prog }, { encoding: 'jsonParsed' }]);
    for (const a of r.value) { const i = a.account.data.parsed.info; if (BY_MINT[i.mint]) bal[i.mint] = (bal[i.mint]||0) + Number(i.tokenAmount.uiAmountString); } }
  } catch (e) { return res.status(502).json({ error: 'Could not read wallet balances: ' + e.message }); }
  const p = await prices().catch(()=>({}));
  const swaps = db.prepare('SELECT * FROM swaps WHERE user_id=? ORDER BY ts DESC').all(req.user.id);
  const cost = {}; for (const s of [...swaps].reverse()) { cost[s.symbol] ??= 0; cost[s.symbol] += s.side==='buy' ? s.usd : -s.usd; }
  const holdings = Object.entries(bal).filter(([,a])=>a>0).map(([mint, amount]) => { const t = BY_MINT[mint], pr = p[mint]?.usdPrice || 0, ch = p[mint]?.priceChange24h || 0, value = amount*pr;
    return { symbol:t.symbol, name:t.name, mint, logo:t.logo, amount, price:pr, change24h:ch, value, pnl24h: value - value/(1+ch/100), costBasis: cost[t.symbol] ?? null }; }).sort((a,b)=>b.value-a.value);
  const total = holdings.reduce((s,h)=>s+h.value,0), stockVal = holdings.filter(h=>h.symbol!=='USDC').reduce((s,h)=>s+h.value,0);
  const net = Object.values(cost).reduce((s,v)=>s+v,0);
  res.json({ wallet:req.user.wallet, total, pnl24h: holdings.reduce((s,h)=>s+h.pnl24h,0), pnlAll: swaps.length ? stockVal - net : null,
    feesPaid: swaps.reduce((s,x)=>s+(x.fee_usd||0),0), holdings, swaps: swaps.slice(0,25) });
});

// Watchlist
app.get('/api/watchlist', auth, (req, res) => res.json(db.prepare('SELECT mint FROM watch WHERE user_id=?').all(req.user.id).map(r=>r.mint)));
app.post('/api/watchlist', auth, (req, res) => {
  const p = z.object({ mint: z.string().refine(m=>STOCKS.some(t=>t.mint===m)), on: z.boolean() }).safeParse(req.body); if (!p.success) return bad(res, 'Bad token');
  db.prepare(p.data.on ? 'INSERT OR IGNORE INTO watch VALUES(?,?)' : 'DELETE FROM watch WHERE user_id=? AND mint=?').run(req.user.id, p.data.mint); res.json({ ok:true });
});

// Swap via Jupiter, 1% platform fee on every buy and sell
const swapIn = z.object({ symbol: z.string().refine(s=>STOCKS.some(t=>t.symbol===s)), side: z.enum(['buy','sell']), amount: z.number().positive().max(1e7), slippageBps: z.number().int().min(10).max(500).default(100) });
function legs(d) { const t = STOCKS.find(x=>x.symbol===d.symbol); const [i,o] = d.side==='buy' ? [USDC,t] : [t,USDC];
  return { t, i, o, raw: BigInt(Math.floor(d.amount * 10**i.decimals)) }; }
function ataOf(owner, tok) { return PublicKey.findProgramAddressSync([new PublicKey(owner).toBytes(), new PublicKey(tok.program).toBytes(), new PublicKey(tok.mint).toBytes()], new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'))[0].toBase58(); }
// All fees are taken in USDC. Sells: Jupiter platform fee on the USDC output.
// Buys: 1% of the USDC input is split off and sent to the fee wallet's USDC account in the same transaction; the rest is swapped.
async function quote(d) { const { i, o, raw } = legs(d);
  const buy = d.side === 'buy', fee = buy ? raw * BigInt(FEE_BPS) / 10000n : 0n, amt = raw - fee;
  const u = `${JUP}/swap/v1/quote?inputMint=${i.mint}&outputMint=${o.mint}&amount=${amt}&slippageBps=${d.slippageBps}` + (buy ? '' : `&platformFeeBps=${FEE_BPS}`);
  const j = await jfetch(u);
  return { q: j, feeRaw: buy ? fee : BigInt(j.platformFee?.amount || 0) }; }
app.post('/api/quote', auth, async (req, res) => {
  const p = swapIn.safeParse(req.body); if (!p.success) return bad(res, 'Bad swap input');
  try { const { q, feeRaw } = await quote(p.data); const { o } = legs(p.data);
    res.json({ outAmount: Number(q.outAmount)/10**o.decimals, minOut: Number(q.otherAmountThreshold)/10**o.decimals, fee: Number(feeRaw)/1e6, feeBps: FEE_BPS, feeSymbol: 'USDC', priceImpactPct: Number(q.priceImpactPct) });
  } catch (e) { res.status(502).json({ error: e.message }); }
});
const conn = new Connection(RPC, 'confirmed');
const ix = x => new TransactionInstruction({ programId: new PublicKey(x.programId), keys: x.accounts.map(a => ({ pubkey: new PublicKey(a.pubkey), isSigner: a.isSigner, isWritable: a.isWritable })), data: Buffer.from(x.data, 'base64') });
function usdcFeeTransfer(owner, amount) { // SPL TransferChecked user USDC ATA -> fee wallet USDC ATA
  const data = Buffer.alloc(10); data[0] = 12; data.writeBigUInt64LE(amount, 1); data[9] = USDC.decimals;
  return new TransactionInstruction({ programId: new PublicKey(USDC.program), data, keys: [
    { pubkey: new PublicKey(ataOf(owner, USDC)), isSigner:false, isWritable:true }, { pubkey: new PublicKey(USDC.mint), isSigner:false, isWritable:false },
    { pubkey: new PublicKey(ataOf(FEE_WALLET, USDC)), isSigner:false, isWritable:true }, { pubkey: new PublicKey(owner), isSigner:true, isWritable:false } ] }); }
app.post('/api/swap', auth, async (req, res) => {
  if (!req.user.wallet) return bad(res, 'Link a wallet first');
  if (!FEE_WALLET) return res.status(503).json({ error: 'Trading is not enabled yet (fee wallet not configured)' });
  const p = swapIn.safeParse(req.body); if (!p.success) return bad(res, 'Bad swap input');
  try { const { q, feeRaw } = await quote(p.data); // re-quote server side so the client can't strip the fee
    const base = { quoteResponse:q, userPublicKey:req.user.wallet, dynamicComputeUnitLimit:true, prioritizationFeeLamports:'auto' };
    if (p.data.side === 'sell') {
      const j = await jpost('/swap/v1/swap', { ...base, feeAccount: ataOf(FEE_WALLET, USDC) });
      return res.json({ tx: j.swapTransaction, lastValidBlockHeight: j.lastValidBlockHeight });
    }
    const j = await jpost('/swap/v1/swap-instructions', base);
    const alts = (await Promise.all((j.addressLookupTableAddresses||[]).map(a => conn.getAddressLookupTable(new PublicKey(a))))).map(r => r.value).filter(Boolean);
    const { blockhash, lastValidBlockHeight } = await conn.getLatestBlockhash();
    const ixs = [...(j.computeBudgetInstructions||[]).map(ix), usdcFeeTransfer(req.user.wallet, feeRaw), ...(j.setupInstructions||[]).map(ix), ix(j.swapInstruction), ...(j.cleanupInstruction ? [ix(j.cleanupInstruction)] : [])];
    const msg = new TransactionMessage({ payerKey: new PublicKey(req.user.wallet), recentBlockhash: blockhash, instructions: ixs }).compileToV0Message(alts);
    res.json({ tx: Buffer.from(new VersionedTransaction(msg).serialize()).toString('base64'), lastValidBlockHeight });
  } catch (e) { res.status(502).json({ error: e.message }); }
});
const jpost = (path, body) => jfetch(JUP + path, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
app.post('/api/swaps/record', auth, async (req, res) => {
  const p = z.object({ sig: z.string().min(60).max(100), symbol: z.string(), side: z.enum(['buy','sell']), inAmt: z.number(), outAmt: z.number() }).safeParse(req.body);
  if (!p.success || !STOCKS.some(t=>t.symbol===p.data.symbol)) return bad(res, 'Bad record');
  const d = p.data, usd = d.side==='buy' ? d.inAmt : d.outAmt;
  try { db.prepare('INSERT INTO swaps(user_id,sig,side,symbol,in_amt,out_amt,usd,fee_usd,ts) VALUES(?,?,?,?,?,?,?,?,?)').run(req.user.id, d.sig, d.side, d.symbol, d.inAmt, d.outAmt, usd, usd*FEE_BPS/1e4, Date.now()); res.json({ ok:true }); }
  catch { bad(res, 'Already recorded'); }
});

app.get('/vendor/web3.js', (req, res) => res.sendFile(new URL('./node_modules/@solana/web3.js/lib/index.iife.min.js', import.meta.url).pathname));
app.use(express.static('public', { extensions:['html'] }));
app.listen(PORT, () => console.log('listening on', PORT, FEE_WALLET ? '' : '(FEE_WALLET not set: trading disabled)'));
