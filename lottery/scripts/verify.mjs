// 独立复算脚本:只用公开数据验证抽奖结果(与 static/app.js 同一套算法)
// 用法: node verify.mjs <session.json>   (session.json 为 GET /api/sessions/:id 的返回)
import fs from 'node:fs';

const enc = new TextEncoder();
async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const unhex = s => new Uint8Array(s.match(/../g).map(h => parseInt(h, 16)));
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
async function randU64(seed, counter) {
  const buf = new Uint8Array(seed.length + 8);
  buf.set(seed, 0);
  new DataView(buf.buffer).setBigUint64(seed.length, BigInt(counter), false);
  const h = await sha256(buf);
  return new DataView(h.buffer).getBigUint64(0, false);
}

(async () => {
  const s = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  let ok = true;

  const lh = hex(await sha256(enc.encode(s.participants.map(p => `${p.id}:${p.name}`).join('\n'))));
  console.log((lh === s.list_hash ? '✓' : '✗') + ' list_hash  ' + lh);
  ok &&= lh === s.list_hash;

  const cm = hex(await sha256(unhex(s.server_seed)));
  console.log((cm === s.commitment ? '✓' : '✗') + ' commitment ' + cm);
  ok &&= cm === s.commitment;

  const seed = await sha256(concat(enc.encode('lottery-v1'), unhex(s.server_seed), unhex(s.public_random.value), unhex(s.list_hash)));
  console.log('  seed       ' + hex(seed));

  const pool = s.participants.map(p => ({ ...p }));
  const winners = [];
  let counter = 0n;
  for (const prize of s.prizes) {
    for (let i = 0; i < prize.count && pool.length; i++) {
      const r = await randU64(seed, counter);
      counter += 1n;
      const j = Number(r % BigInt(pool.length));
      const [w] = pool.splice(j, 1);
      winners.push({ prize: prize.name, id: w.id, name: w.name });
    }
  }
  const same = JSON.stringify(winners) === JSON.stringify(s.winners);
  console.log((same ? '✓' : '✗') + ' winners    ' + (same ? '复算结果与公布结果一致' : '不一致!'));
  console.log('  中奖名单: ' + winners.map(w => `${w.prize}:${w.name}`).join('  '));
  ok &&= same;

  console.log(ok ? '\n全部校验通过' : '\n校验失败!');
  process.exit(ok ? 0 : 1);
})();
