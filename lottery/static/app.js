import { html, render, useState, useEffect } from './vendor/htm-preact.js';

// ---------------------------------------------------------------------------
// 独立复算实现 —— 与后端 src/main.rs 中的协议逐字节一致。
// 任何人都可以只凭本页面拿到的公开数据,在浏览器里重新算一遍,
// 不信任服务器返回的"结果",只信任公开数据 + 公开算法。
// ---------------------------------------------------------------------------
const enc = new TextEncoder();

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
function hex(bytes) {
  return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
}
function unhex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
}
function concat(...arrs) {
  const n = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function canonicalList(participants) {
  return participants.map(p => `${p.id}:${p.name}`).join('\n');
}
async function randU64(seed, counter) {
  const buf = new Uint8Array(seed.length + 8);
  buf.set(seed, 0);
  new DataView(buf.buffer).setBigUint64(seed.length, BigInt(counter), false); // 大端
  const h = await sha256(buf);
  return new DataView(h.buffer).getBigUint64(0, false);
}
async function computeDraw(participants, prizes, seed) {
  const pool = participants.map(p => ({ ...p }));
  const winners = [];
  let counter = 0n;
  for (const prize of prizes) {
    for (let i = 0; i < prize.count; i++) {
      if (pool.length === 0) return winners;
      const r = await randU64(seed, counter);
      counter += 1n;
      const j = Number(r % BigInt(pool.length));
      const [w] = pool.splice(j, 1);
      winners.push({ prize: prize.name, id: w.id, name: w.name });
    }
  }
  return winners;
}

// 完整复算:返回每一步的校验结果
async function verifyAll(s) {
  const checks = [];
  const lh = hex(await sha256(enc.encode(canonicalList(s.participants))));
  checks.push({
    label: '名单摘要:对当前名单重算 SHA-256,与开奖前公布的 list_hash 对比',
    value: lh, expect: s.list_hash, ok: lh === s.list_hash,
  });
  const cm = hex(await sha256(unhex(s.server_seed)));
  checks.push({
    label: '承诺开启:对开奖后公开的 server_seed 求 SHA-256,与开奖前公布的承诺值对比',
    value: cm, expect: s.commitment, ok: cm === s.commitment,
  });
  const seed = await sha256(concat(
    enc.encode('lottery-v1'), unhex(s.server_seed), unhex(s.public_random.value), unhex(s.list_hash)));
  checks.push({
    label: '最终种子:SHA-256("lottery-v1" ‖ server_seed ‖ public_random ‖ list_hash)',
    value: hex(seed), expect: null, ok: true,
  });
  const winners = await computeDraw(s.participants, s.prizes, seed);
  const same = JSON.stringify(winners) === JSON.stringify(s.winners);
  checks.push({
    label: '重算中奖名单:用最终种子按公开算法重新抽取,与公布结果对比',
    value: same ? '一致' : '不一致', expect: null, ok: same,
  });
  return { checks, winners };
}

// ---------------------------------------------------------------------------
const api = {
  async list() { return (await fetch('/api/sessions')).json(); },
  async get(id) { return (await fetch(`/api/sessions/${id}`)).json(); },
  async create(body) {
    const r = await fetch('/api/sessions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
  async draw(id) {
    const r = await fetch(`/api/sessions/${id}/draw`, { method: 'POST' });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },
};

const fmtTime = t => new Date(t * 1000).toLocaleString();

function CreateForm({ onCreated }) {
  const [name, setName] = useState('2026 年会抽奖');
  const [names, setNames] = useState('张三\n李四\n王五\n赵六\n孙七\n周八\n吴九\n郑十');
  const [prizes, setPrizes] = useState('三等奖,3\n二等奖,2\n一等奖,1');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setErr(''); setBusy(true);
    try {
      const participants = names.split('\n').map(s => s.trim()).filter(Boolean)
        .map((n, i) => ({ id: String(i + 1).padStart(3, '0'), name: n }));
      const prizeList = prizes.split('\n').map(s => s.trim()).filter(Boolean).map(line => {
        const [pname, c] = line.split(/[,，]/).map(s => s.trim());
        return { name: pname, count: parseInt(c, 10) };
      });
      if (!participants.length) throw new Error('名单为空');
      if (prizeList.some(p => !p.name || !(p.count > 0))) throw new Error('奖项格式应为:奖项名,数量');
      const total = prizeList.reduce((s, p) => s + p.count, 0);
      if (total > participants.length) throw new Error('奖项总数超过人数');
      onCreated(await api.create({ name, participants, prizes: prizeList }));
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  return html`<div class="card">
    <h2>1. 创建抽奖(开奖前)</h2>
    <label>活动名称</label>
    <input type="text" value=${name} onInput=${e => setName(e.target.value)} />
    <label>参与名单(每行一个名字,编号自动生成)</label>
    <textarea value=${names} onInput=${e => setNames(e.target.value)}></textarea>
    <label>奖项(每行:奖项名,数量 —— 按顺序抽取,先小奖后大奖)</label>
    <textarea value=${prizes} onInput=${e => setPrizes(e.target.value)} style="min-height:70px"></textarea>
    <button disabled=${busy} onClick=${submit}>提交并公布承诺</button>
    ${err && html`<p class="err">${err}</p>`}
    <p class="muted">提交后服务器会公布:名单、名单摘要 list_hash、承诺值 commitment。
    此后任何人改动名单或服务器私换种子,开奖后复算都会失败。</p>
  </div>`;
}

function SessionCard({ s, onOpen, onDraw, busy }) {
  return html`<div class="card">
    <b>${s.name}</b> <span class="pill">${s.status === 'drawn' ? '已开奖' : '已承诺待开奖'}</span>
    <div class="muted">承诺时间:${fmtTime(s.committed_at)} · ${s.participants.length} 人 ·
      ${s.prizes.map(p => `${p.name}×${p.count}`).join(' / ')}</div>
    <div class="mono">list_hash: ${s.list_hash}</div>
    <div class="mono">commitment: ${s.commitment}</div>
    <button onClick=${() => onOpen(s.id)}>查看 / 验证</button>
    ${s.status !== 'drawn' && html` <button class="ghost" disabled=${busy} onClick=${() => onDraw(s.id)}>开奖</button>`}
  </div>`;
}

function VerifyPanel({ s }) {
  const [result, setResult] = useState(null);
  useEffect(() => {
    if (s.status === 'drawn') verifyAll(s).then(setResult);
  }, [s.id, s.status]);
  if (s.status !== 'drawn') return null;
  if (!result) return html`<p>正在本地复算…</p>`;
  const allOk = result.checks.every(c => c.ok);
  return html`<div class="card">
    <h2>3. 独立复算(全部在你的浏览器内完成)</h2>
    <p class=${allOk ? 'ok' : 'bad'}>${allOk ? '✓ 全部校验通过:结果与公开数据自洽,名单与种子均未被动过。'
      : '✗ 校验失败:公开数据对不上,有人动过手脚!'}</p>
    ${result.checks.map(c => html`<div class="card">
      <div class=${c.ok ? 'ok' : 'bad'}>${c.ok ? '✓' : '✗'} ${c.label}</div>
      <div class="mono">${c.value}</div>
      ${c.expect && html`<div class="mono muted">公布值: ${c.expect}</div>`}
    </div>`)}
    <p class="muted">公开随机源(本地模拟):第 ${s.public_random.round} 轮,
      生成于 ${fmtTime(s.public_random.generated_at)}(晚于承诺时间 ${fmtTime(s.committed_at)}),
      值 <span class="mono">${s.public_random.value}</span>。
      承诺在先、随机源在后,因此服务器无法在承诺时预知最终种子。</p>
  </div>`;
}

function SessionDetail({ s, onBack, onDraw, busy }) {
  return html`<div>
    <p><a onClick=${onBack}>← 返回列表</a></p>
    <h1>${s.name} <span class="pill">${s.status === 'drawn' ? '已开奖' : '已承诺待开奖'}</span></h1>
    <div class="card">
      <h2>开奖前公布(承诺)</h2>
      <div class="mono">list_hash(SHA-256 名单摘要): ${s.list_hash}</div>
      <div class="mono">commitment(服务器种子承诺): ${s.commitment}</div>
      <div class="muted">承诺时间:${fmtTime(s.committed_at)}</div>
      <table><tr><th>#</th><th>编号</th><th>姓名</th></tr>
        ${s.participants.map((p, i) => html`<tr><td>${i + 1}</td><td>${p.id}</td><td>${p.name}</td></tr>`)}
      </table>
      ${s.status !== 'drawn' && html`<button disabled=${busy} onClick=${() => onDraw(s.id)}>开奖(取当前轮公开随机源)</button>`}
    </div>
    ${s.status === 'drawn' && html`<div class="card">
      <h2>2. 开奖结果</h2>
      <div class="mono">server_seed(开奖后公开): ${s.server_seed}</div>
      <div class="mono">public_random(公开随机源): ${s.public_random.value}</div>
      <table><tr><th>奖项</th><th>编号</th><th>姓名</th></tr>
        ${s.winners.map(w => html`<tr class="winner"><td>${w.prize}</td><td>${w.id}</td><td><b>${w.name}</b></td></tr>`)}
      </table>
    </div>`}
    <${VerifyPanel} s=${s} />
  </div>`;
}

function App() {
  const [sessions, setSessions] = useState([]);
  const [current, setCurrent] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function refresh() { setSessions(await api.list()); }
  useEffect(() => { refresh(); }, []);

  async function open(id) { setCurrent(await api.get(id)); }
  async function doDraw(id) {
    setBusy(true); setErr('');
    try {
      const s = await api.draw(id);
      await refresh();
      if (current && current.id === id) setCurrent(s); else setCurrent(s);
    } catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  if (current) {
    return html`<${SessionDetail} s=${current} busy=${busy}
      onBack=${() => { setCurrent(null); refresh(); }} onDraw=${doDraw} />`;
  }
  return html`<div>
    <h1>公开可验证抽奖</h1>
    <p class="muted">原理:开奖前公布名单摘要和服务器种子的承诺值;开奖时结合承诺之后
    才产生的公开随机源计算结果;开奖后公开服务器种子。任何人都能在下方独立复算,
    名单被改、种子被换、结果被编,都会被发现。</p>
    <${CreateForm} onCreated=${s => { refresh(); setCurrent(s); }} />
    <h2>已有场次</h2>
    ${err && html`<p class="err">${err}</p>`}
    ${sessions.map(s => html`<${SessionCard} s=${s} busy=${busy} onOpen=${open} onDraw=${doDraw} />`)}
  </div>`;
}

render(html`<${App} />`, document.getElementById('app'));
