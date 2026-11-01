const $ = s => document.querySelector(s); let me = null, tokens = [], csrf = '';
const fmt = n => n == null ? '–' : '$' + Number(n).toLocaleString(undefined, { maximumFractionDigits: 2, minimumFractionDigits: 2 });
const pct = n => n == null ? '–' : (n >= 0 ? '+' : '') + n.toFixed(2) + '%';
const cls = n => n >= 0 ? 'up' : 'dn';
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function api(path, body) {
  const r = await fetch('/api/' + path, body ? { method: 'POST', headers: { 'content-type': 'application/json', 'x-csrf-token': csrf }, body: JSON.stringify(body) } : {});
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || (r.status === 429 ? 'Too many attempts. Wait a few minutes and try again.' : 'Request failed (' + r.status + '). Please try again.')); return j;
}
function show(v) { document.querySelectorAll('.view').forEach(e => e.hidden = e.id !== 'v-' + v); $('#nav').hidden = !me; window.scrollTo(0, 0); }
const COLORS = ['#7c5cff', '#22c55e', '#f59e0b', '#06b6d4', '#ef4444', '#ec4899', '#84cc16', '#a78bfa', '#14b8a6', '#f97316', '#64748b'];

async function route() {
  const [h, q] = location.hash.slice(1).split('?'); const params = new URLSearchParams(q || '');
  if (!me) { try { me = await api('me'); csrf = me.csrf; } catch { me = null; } }
  if (!tokens.length) tokens = await api('tokens').catch(() => []);
  if (!me) { if (invite() && !h) return authView('signup'); if (h === 'signup' || h === 'login') return authView(h); renderTicker(); return show('landing'); }
  if (!me.wallet) return show('connect');
  if (h === 'markets') return markets();
  if (h === 'swap') return swapView(params);
  return dash();
}
function renderTicker() { $('#ticker').innerHTML = tokens.slice(0, 8).map(t => `<div class="tk"><b>${esc(t.symbol)}</b> ${fmt(t.price)} <span class="${cls(t.change24h)}">${pct(t.change24h)}</span></div>`).join(''); }

(() => { const i = new URLSearchParams(location.search).get('invite'); if (i) { sessionStorage.setItem('invite', i); history.replaceState(null, '', location.pathname + location.hash); } })();
const invite = () => sessionStorage.getItem('invite');
function authView(mode) {
  const su = mode === 'signup'; show('auth');
  $('#auth-title').textContent = su ? 'Create your account' : 'Welcome back'; $('#auth-btn').textContent = su ? 'Create account' : 'Log in'; $('#auth-err').textContent = '';
  $('#us-row').hidden = !su || !!invite(); $('#auth-switch').innerHTML = su ? 'Have an account? <a href="#login">Log in</a>' : 'New here? <a href="#signup">Create an account</a>';
  $('#auth-form').noValidate = true;
  $('#auth-form').onsubmit = async e => {
    e.preventDefault(); const f = new FormData(e.target), btn = $('#auth-btn'), err = $('#auth-err');
    const fail = m => { err.textContent = m; err.scrollIntoView({ block: 'center', behavior: 'smooth' }); };
    err.textContent = ''; const email = String(f.get('email') || '').trim(), password = String(f.get('password') || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return fail('Enter a valid email address.');
    if (su && password.length < 10) return fail('Password must be at least 10 characters.');
    if (su && !invite() && f.get('notUS') !== 'on') return fail('Please tick the box to confirm you are not a US person.');
    const label = btn.textContent; btn.disabled = true; btn.textContent = su ? 'Creating account…' : 'Logging in…';
    try { const r = await api(su ? 'signup' : 'login', { email, password, ...(su ? { notUS: f.get('notUS') === 'on', ...(invite() ? { invite: invite() } : {}) } : {}) });
      csrf = r.csrf; me = null; sessionStorage.removeItem('invite'); location.hash = '#dash'; route();
    } catch (x) { if (/invite/i.test(x.message)) { sessionStorage.removeItem('invite'); $('#us-row').hidden = false; } fail(x.message || 'Something went wrong. Please try again.'); }
    finally { btn.disabled = false; btn.textContent = label; }
  };
}
$('#logout').onclick = async () => { await api('logout', {}).catch(() => {}); me = null; location.hash = ''; route(); };

const phantom = () => window.phantom?.solana?.isPhantom ? window.phantom.solana : null;
$('#connect').onclick = async () => {
  const p = phantom(); $('#connect-err').textContent = '';
  if (!p) { if (/Android|iPhone|iPad/i.test(navigator.userAgent)) location.href = 'https://phantom.app/ul/browse/' + encodeURIComponent(location.href) + '?ref=' + encodeURIComponent(location.origin); else $('#connect-err').textContent = 'Phantom not found. Install it, then refresh.'; return; }
  try { const { publicKey } = await p.connect(); const { message } = await api('wallet/nonce', {});
    const { signature } = await p.signMessage(new TextEncoder().encode(message), 'utf8');
    await api('wallet/verify', { address: publicKey.toString(), signature: solanaWeb3.bs58 ? solanaWeb3.bs58.encode(signature) : b58(signature) });
    me = null; location.hash = '#dash'; route(); } catch (e) { $('#connect-err').textContent = e.message; }
};
function b58(bytes) { const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; let d = [0], s = '';
  for (const b of bytes) { let c = b; for (let j = 0; j < d.length; j++) { c += d[j] << 8; d[j] = c % 58; c = c / 58 | 0; } while (c) { d.push(c % 58); c = c / 58 | 0; } }
  for (const b of bytes) { if (b) break; s += '1'; } return s + d.reverse().map(x => A[x]).join(''); }

async function dash() {
  show('dash'); $('#d-err').textContent = ''; const watch = await api('watchlist').catch(() => []);
  $('#d-watch').innerHTML = tokens.filter(t => watch.includes(t.mint)).map(row).join('') || '<li class="muted">Tap ☆ on Markets to watch a stock.</li>';
  try { const p = await api('portfolio');
    $('#d-total').textContent = fmt(p.total); $('#d-wallet').textContent = 'Wallet ' + p.wallet.slice(0, 4) + '…' + p.wallet.slice(-4);
    $('#d-24h').innerHTML = `24h <span class="${cls(p.pnl24h)}">${fmt(p.pnl24h)}</span>`;
    $('#d-all').innerHTML = p.pnlAll == null ? 'All-time: trade to track' : `All-time <span class="${cls(p.pnlAll)}">${fmt(p.pnlAll)}</span>`;
    $('#d-hold').innerHTML = p.holdings.map(h => `<li>${h.logo ? `<img src="${esc(h.logo)}" alt="">` : '<span class="tk">$</span>'}<div class="grow"><b>${esc(h.symbol)}</b><div class="muted small">${h.amount.toFixed(4)} · ${fmt(h.price)}</div></div><div class="r">${fmt(h.value)}<div class="small ${cls(h.change24h)}">${pct(h.change24h)}</div></div>${h.symbol !== 'USDC' ? `<a class="btn ghost" href="#swap?side=sell&sym=${esc(h.symbol)}">Sell</a>` : ''}</li>`).join('') || '<li class="muted">No stocks yet. <a href="#markets">Browse markets</a></li>';
    let acc = 0; const segs = p.holdings.filter(h => h.value > 0).map((h, i) => { const a = acc; acc += h.value / p.total * 360; return [h, COLORS[i % COLORS.length], a, acc]; });
    $('#d-donut').style.background = segs.length ? `conic-gradient(${segs.map(([, c, a, b]) => `${c} ${a}deg ${b}deg`).join(',')})` : '#222b3b';
    $('#d-legend').innerHTML = segs.map(([h, c]) => `<li><i data-c="${c}"></i>${esc(h.symbol)} ${(h.value / p.total * 100).toFixed(1)}%</li>`).join('') || '<li class="muted">Nothing yet</li>';
    document.querySelectorAll('#d-legend i').forEach(i => i.style.background = i.dataset.c);
    $('#d-fees').textContent = `· fees paid ${fmt(p.feesPaid)}`;
    $('#d-tx').innerHTML = p.swaps.map(s => `<li><div class="grow"><b class="${s.side === 'buy' ? 'up' : 'dn'}">${s.side.toUpperCase()}</b> ${esc(s.symbol)}<div class="muted small">${new Date(s.ts).toLocaleString()}</div></div><div class="r">${fmt(s.usd)}<div class="small"><a href="https://solscan.io/tx/${esc(s.sig)}" target="_blank" rel="noopener">Solscan ↗</a></div></div></li>`).join('') || '<li class="muted">No trades yet</li>';
  } catch (e) { $('#d-err').textContent = e.message; }
}
document.addEventListener('click', e => { const s = e.target.closest('.star'); if (!s) return; const on = !s.classList.contains('on'); s.classList.toggle('on', on); s.textContent = on ? '★' : '☆'; api('watchlist', { mint: s.dataset.mint, on }); });
const row = (t, star) => `<li><img src="${esc(t.logo)}" alt=""><div class="grow"><b>${esc(t.symbol)}</b><div class="muted small">${esc(t.name)}</div></div><div class="r">${fmt(t.price)}<div class="small ${cls(t.change24h)}">${pct(t.change24h)}</div></div><a class="btn" href="#swap?side=buy&sym=${esc(t.symbol)}">Buy</a>${star != null ? `<button class="star ${star ? 'on' : ''}" data-mint="${esc(t.mint)}" aria-label="Watch">${star ? '★' : '☆'}</button>` : ''}</li>`;
async function markets() { show('markets'); tokens = await api('tokens').catch(() => tokens); const w = await api('watchlist').catch(() => []); $('#m-list').innerHTML = tokens.map(t => row(t, w.includes(t.mint))).join(''); }

let side = 'buy', qTimer;
function swapView(params) {
  show('swap'); side = params.get('side') === 'sell' ? 'sell' : 'buy';
  $('#s-sym').innerHTML = tokens.map(t => `<option ${t.symbol === params.get('sym') ? 'selected' : ''}>${esc(t.symbol)}</option>`).join(''); setSide(side);
}
function setSide(s) { side = s; document.querySelectorAll('.seg button').forEach(b => b.classList.toggle('on', b.dataset.side === s)); $('#s-in-lbl').textContent = s === 'buy' ? 'You pay (USDC)' : `You sell (${$('#s-sym').value})`; requote(); }
document.querySelectorAll('.seg button').forEach(b => b.onclick = () => setSide(b.dataset.side));
$('#s-sym').onchange = () => setSide(side); $('#s-amt').oninput = () => { clearTimeout(qTimer); qTimer = setTimeout(requote, 400); };
const body = () => ({ symbol: $('#s-sym').value, side, amount: Number($('#s-amt').value) });
async function requote() {
  $('#s-go').disabled = true; $('#s-err').textContent = ''; const b = body(); if (!(b.amount > 0)) return;
  $('#s-quote').innerHTML = '<span class="muted">Getting best price…</span>';
  try { const q = await api('quote', b); const o = side === 'buy' ? b.symbol : 'USDC';
    $('#s-quote').innerHTML = `<div><span>You receive</span><b>${q.outAmount.toFixed(6)} ${esc(o)}</b></div><div><span class="muted">Minimum (after slippage)</span><span>${q.minOut.toFixed(6)}</span></div><div><span class="muted">Platform fee (${q.feeBps / 100}%)</span><span>${q.fee.toFixed(6)} ${esc(q.feeSymbol)}</span></div><div><span class="muted">Price impact</span><span>${(q.priceImpactPct * 100).toFixed(3)}%</span></div>`;
    $('#s-go').disabled = false; $('#s-go').dataset.out = q.outAmount;
  } catch (e) { $('#s-quote').innerHTML = ''; $('#s-err').textContent = e.message; }
}
$('#s-go').onclick = async () => {
  const p = phantom(); if (!p) return $('#s-err').textContent = 'Open this site in Phantom to trade.';
  const b = body(); $('#s-go').disabled = true;
  try { const { tx } = await api('swap', b); await p.connect();
    if (p.publicKey.toString() !== me.wallet) throw new Error('Switch Phantom to your linked wallet');
    const vtx = solanaWeb3.VersionedTransaction.deserialize(Uint8Array.from(atob(tx), c => c.charCodeAt(0)));
    const { signature } = await p.signAndSendTransaction(vtx);
    await api('swaps/record', { sig: signature, symbol: b.symbol, side, inAmt: b.amount, outAmt: Number($('#s-go').dataset.out) });
    $('#s-quote').innerHTML = `✅ Sent! <a href="https://solscan.io/tx/${esc(signature)}" target="_blank" rel="noopener">View on Solscan</a>`;
  } catch (e) { $('#s-err').textContent = e.message; } finally { $('#s-go').disabled = false; }
};
addEventListener('hashchange', route); route();
