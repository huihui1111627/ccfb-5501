/* shared helpers */
const API = {
  async get(path) {
    const r = await fetch(path);
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'request failed');
    return j;
  },
  async post(path, body) {
    const r = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    const j = await r.json();
    if (!j.ok) throw new Error(j.error || 'request failed');
    return j;
  },
};

function toast(msg, isErr) {
  let el = document.querySelector('.toast');
  if (!el) {
    el = document.createElement('div');
    el.className = 'toast';
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.toggle('err', !!isErr);
  el.classList.add('show');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove('show'), 3200);
}

function fmt(n, digits) {
  if (n === null || n === undefined) return '—';
  if (typeof n !== 'number') return n;
  if (digits !== undefined) return n.toFixed(digits);
  return n.toLocaleString('en-US');
}

function bytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  return (n / 1048576).toFixed(1) + ' MB';
}

function dur(s) {
  s = Math.max(0, Math.floor(s || 0));
  const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60), sec = s % 60;
  return (h ? h + 'h ' : '') + (m ? m + 'm ' : '') + sec + 's';
}

function esc(s) {
  return String(s === null || s === undefined ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function hexdump(bytesArray, perLine = 32) {
  const lines = [];
  for (let i = 0; i < bytesArray.length; i += perLine) {
    const slice = bytesArray.slice(i, i + perLine);
    const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
    lines.push(i.toString(16).padStart(4, '0') + '  ' + hex);
  }
  return lines.join('\n');
}

function lineChart(canvas, series, opts) {
  opts = opts || {};
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  const W = rect.width, H = rect.height;
  const padL = 42, padR = 10, padT = 10, padB = 22;
  ctx.clearRect(0, 0, W, H);

  let maxY = 0;
  series.forEach(s => s.points.forEach(p => { if (p[1] > maxY) maxY = p[1]; }));
  if (maxY <= 0) maxY = 1;
  maxY *= 1.15;
  const n = Math.max(2, ...series.map(s => s.points.length));

  ctx.strokeStyle = 'rgba(255,255,255,0.07)';
  ctx.fillStyle = '#8294a6';
  ctx.font = '10px ui-monospace, monospace';
  ctx.textAlign = 'right';
  for (let i = 0; i <= 4; i++) {
    const y = padT + (H - padT - padB) * i / 4;
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    const val = maxY * (1 - i / 4);
    ctx.fillText(val >= 1000 ? (val / 1000).toFixed(1) + 'k' : val.toFixed(val < 10 ? 1 : 0), padL - 6, y + 3);
  }

  series.forEach(s => {
    if (!s.points.length) return;
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    s.points.forEach((p, i) => {
      const x = padL + (W - padL - padR) * (n === 1 ? 0 : i / (n - 1));
      const y = padT + (H - padT - padB) * (1 - p[1] / maxY);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
    if (s.fill) {
      ctx.lineTo(W - padR, H - padB);
      ctx.lineTo(padL, H - padB);
      ctx.closePath();
      ctx.globalAlpha = 0.10;
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.globalAlpha = 1;
    }
  });

  ctx.textAlign = 'left';
  ctx.fillStyle = '#8294a6';
  const span = opts.span || 60;
  ctx.fillText('−' + dur(span), padL, H - 6);
  ctx.textAlign = 'right';
  ctx.fillText('now', W - padR, H - 6);
}

async function refreshRunState() {
  try {
    const j = await API.get('/api/status');
    const st = j.status;
    const dot = document.getElementById('statedot');
    const txt = document.getElementById('statetext');
    if (dot && txt) {
      dot.className = 'dot ' + (st.running ? 'running' : 'stopped');
      txt.textContent = (st.running ? '运行中 · ' : '已停止 · ')
        + fmt(st.exec_rate, 0) + ' exec/s · '
        + fmt(st.edges) + ' 边 · ' + fmt(st.buckets) + ' 桶';
    }
  } catch (e) { /* console booting */ }
}
setInterval(refreshRunState, 3000);
document.addEventListener('DOMContentLoaded', refreshRunState);
