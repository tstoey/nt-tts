#!/usr/bin/env node
// Builds the GitHub Pages copy of the requirement checklist.
//
//   node scripts/build.mjs              asks for the page password (typed in, never stored)
//   PAGE_PASSWORD=... node scripts/build.mjs   (or set it in the environment, e.g. in CI)
//   node scripts/build.mjs --out <dir>  write somewhere other than docs/ (for testing)
//
// 1. Reads src/index.src.html (the team copy, never committed).
// 2. Removes team-only parts: <!--team-->…<!--/team--> blocks and tn:"…" notes, and sets TEAM = false.
// 3. Encrypts the whole page: PBKDF2-SHA256 (600,000 rounds) → AES-256-GCM. GitHub Pages is public,
//    so the repository only ever holds this encrypted file; the page decrypts it in the browser.
// 4. Writes docs/index.html and docs/.nojekyll, then decrypts its own output to check it.
//
// Needs Node 20+ and nothing else.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { gzipSync, gunzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SRC = path.join(ROOT, "src", "index.src.html");
const outArg = process.argv.indexOf("--out");
const OUT_DIR = outArg > 0 ? path.resolve(process.argv[outArg + 1]) : path.join(ROOT, "docs");
const OUT = path.join(OUT_DIR, "index.html");
const ITER = 600000;
const MIN_LEN = 12;
const { subtle } = globalThis.crypto;

function fail(msg){ console.error("\n✗ " + msg); process.exit(1); }

// ---------- 1–2. the public copy ----------
function publicCopy(src){
  let html = src;
  const blocks = html.match(/<!--team-->[\s\S]*?<!--\/team-->/g) || [];
  html = html.replace(/<!--team-->[\s\S]*?<!--\/team-->/g, "");
  const notes = html.match(/,tn:"(?:[^"\\]|\\.)*"/g) || [];
  html = html.replace(/,tn:"(?:[^"\\]|\\.)*"/g, "");
  const flag = "const TEAM = true;";
  if (html.split(flag).length !== 2) fail("ไม่พบ " + flag + " ใน source พอดี 1 จุด");
  html = html.replace(flag, "const TEAM = false;");

  // anything team-only left behind stops the build
  const leaks = [/<!--\/?team-->/, /tn:"/, /ตรวจภายในก่อน/, /ให้ PM ยืนยัน/, /วิธีถามแบบ (BA|Solution Architect|AI Engineer)/];
  for (const re of leaks) if (re.test(html)) fail("ยังมีส่วนที่ใช้ภายในทีมเหลืออยู่: " + re);

  // the source is a page fragment (head tags, then body); give it a proper document shell
  const cut = html.indexOf("<!-- shared arrowheads");
  if (cut < 0) fail("ไม่พบจุดแบ่ง head/body ใน source");
  const doc = "<!doctype html>\n<html lang=\"th\">\n<head>\n<meta name=\"robots\" content=\"noindex,nofollow\">\n"
    + html.slice(0, cut).trim() + "\n</head>\n<body>\n" + html.slice(cut) + "\n</body>\n</html>\n";
  return {doc, blocks: blocks.length, notes: notes.length};
}

// ---------- 3. password ----------
function askHidden(question){
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) return reject(new Error("ไม่มี terminal ให้พิมพ์รหัสผ่าน ใช้ตัวแปร PAGE_PASSWORD แทน"));
    process.stdout.write(question);
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding("utf8");
    let buf = "";
    const cleanup = () => { stdin.removeListener("data", onData); stdin.setRawMode(false); stdin.pause(); };
    const onData = chunk => {
      for (const c of chunk){
        if (c === "\r" || c === "\n"){ cleanup(); process.stdout.write("\n"); return resolve(buf); }
        if (c === "\u0003"){ cleanup(); process.stdout.write("\n"); process.exit(130); }
        if (c === "\u007f" || c === "\b"){ if (buf){ buf = [...buf].slice(0, -1).join(""); process.stdout.write("\b \b"); } continue; }
        if (c < " ") continue;
        buf += c; process.stdout.write("*");
      }
    };
    stdin.on("data", onData);
  });
}
async function getPassword(){
  if (process.env.PAGE_PASSWORD) return process.env.PAGE_PASSWORD;
  const a = await askHidden("รหัสผ่านของหน้า (อย่างน้อย " + MIN_LEN + " ตัวอักษร): ");
  const b = await askHidden("พิมพ์รหัสผ่านอีกครั้ง: ");
  if (a !== b) fail("รหัสผ่านสองครั้งไม่ตรงกัน");
  return a;
}

// ---------- 3. encryption ----------
const b64 = buf => Buffer.from(buf).toString("base64");
const unb64 = s => new Uint8Array(Buffer.from(s, "base64"));
async function deriveKey(password, salt){
  const base = await subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({name:"PBKDF2", salt, iterations:ITER, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, false, ["encrypt", "decrypt"]);
}
// keep the salt of the previous build, so "จำไว้ในเครื่องนี้" keeps working after a content update with the same password
async function previousSalt(){
  if (!existsSync(OUT)) return null;
  const m = (await readFile(OUT, "utf8")).match(/<script id="payload" type="application\/json">([\s\S]*?)<\/script>/);
  try { const p = JSON.parse(m[1]); return p.salt ? unb64(p.salt) : null; } catch(e){ return null; }
}

// ---------- 4. the locked page ----------
function lockPage(payload){
  return `<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>เอกสารภายใน</title>
<style>
:root{--bg:#F2F5F4;--card:#fff;--ink:#24302D;--muted:#566561;--line:#B8C6C1;--accent:#2F7A6B;--on:#fff;--warn:#A35F0A;--focus:#2F6FD1}
@media (prefers-color-scheme: dark){:root{--bg:#161B1A;--card:#1D2322;--ink:#DCE4E1;--muted:#9BA9A4;--line:#3E4946;--accent:#6FC1AE;--on:#0F211D;--warn:#EBA24F;--focus:#7FB0FF}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:var(--bg);color:var(--ink);font:16px/1.6 "IBM Plex Sans Thai","Noto Sans Thai","Leelawadee UI",Tahoma,sans-serif}
form{width:min(380px,100%);background:var(--card);border:1px solid var(--line);border-radius:12px;padding:24px;display:grid;gap:12px}
h1{margin:0;font-size:20px}
p{margin:0;color:var(--muted);font-size:14.5px}
label{display:grid;gap:4px;font-size:14px}
input[type=password]{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:9px 12px}
.rm{display:flex;gap:8px;align-items:center;color:var(--muted)}
button{font:inherit;font-weight:600;border:0;border-radius:8px;padding:10px;background:var(--accent);color:var(--on);cursor:pointer}
button:disabled{opacity:.6;cursor:default}
#msg{min-height:1.4em;color:var(--warn);font-weight:600}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
</style>
</head>
<body>
<form id="f">
  <h1>เอกสารภายใน</h1>
  <p>ใส่รหัสผ่านที่ได้รับจากทีมเพื่อเปิดหน้านี้</p>
  <label for="pw">รหัสผ่าน<input id="pw" type="password" autocomplete="current-password" required autofocus></label>
  <label class="rm" for="rm"><input type="checkbox" id="rm"> จำไว้ในเครื่องนี้</label>
  <button id="go">เปิด</button>
  <p id="msg" role="alert"></p>
</form>
<script id="payload" type="application/json">${JSON.stringify(payload)}</script>
<script>
(function(){
  "use strict";
  var P = JSON.parse(document.getElementById("payload").textContent);
  var KEY = "tts-req-key";
  var $ = function(id){ return document.getElementById(id); };
  var bytes = function(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); };
  function store(op, v){ try { return op === "get" ? localStorage.getItem(KEY) : op === "set" ? localStorage.setItem(KEY, v) : localStorage.removeItem(KEY); } catch(e){ return null; } }
  if (/[?&]forget\\b/.test(location.search)) store("del");
  if (!window.crypto || !crypto.subtle || typeof DecompressionStream === "undefined"){
    $("msg").textContent = "เบราว์เซอร์นี้เปิดหน้าไม่ได้ ลองใช้ Chrome, Edge, Firefox หรือ Safari รุ่นใหม่";
    $("go").disabled = true; return;
  }
  async function derive(pw){
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2", salt:bytes(P.salt), iterations:P.iter, hash:"SHA-256"}, base, {name:"AES-GCM", length:256}, true, ["decrypt"]);
  }
  async function open(key){
    var plain = await crypto.subtle.decrypt({name:"AES-GCM", iv:bytes(P.iv)}, key, bytes(P.ct));
    var text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
    document.open(); document.write(text); document.close();
  }
  async function tryStored(){
    var raw = store("get"); if (!raw) return;
    try { await open(await crypto.subtle.importKey("raw", bytes(raw), "AES-GCM", false, ["decrypt"])); }
    catch(e){ store("del"); }
  }
  $("f").addEventListener("submit", async function(ev){
    ev.preventDefault();
    $("go").disabled = true; $("msg").textContent = ""; $("go").textContent = "กำลังเปิด…";
    try {
      var key = await derive($("pw").value);
      if ($("rm").checked){ var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key)); store("set", btoa(String.fromCharCode.apply(null, raw))); }
      await open(key);
    } catch(e){
      store("del");
      $("msg").textContent = "รหัสผ่านไม่ถูกต้อง";
      $("go").disabled = false; $("go").textContent = "เปิด"; $("pw").select();
    }
  });
  tryStored();
})();
</script>
</body>
</html>
`;
}

// ---------- run ----------
const src = await readFile(SRC, "utf8").catch(() => fail("ไม่พบ " + path.relative(ROOT, SRC)));
const {doc, blocks, notes} = publicCopy(src);
const password = await getPassword().catch(e => fail(e.message));
if ([...password].length < MIN_LEN) fail("รหัสผ่านสั้นเกินไป ต้องมีอย่างน้อย " + MIN_LEN + " ตัวอักษร");

const salt = (await previousSalt()) || globalThis.crypto.getRandomValues(new Uint8Array(16));
const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
const key = await deriveKey(password, salt);
const packed = gzipSync(Buffer.from(doc, "utf8"), {level:9});
const ct = new Uint8Array(await subtle.encrypt({name:"AES-GCM", iv}, key, packed));
const payload = {v:1, kdf:"PBKDF2-SHA256", iter:ITER, cipher:"AES-256-GCM", gz:true, salt:b64(salt), iv:b64(iv), ct:b64(ct)};
const page = lockPage(payload);

// self-check: the file decrypts back to the same page, and no readable content is left in it
const check = await subtle.decrypt({name:"AES-GCM", iv}, await deriveKey(password, salt), ct);
if (gunzipSync(Buffer.from(check)).toString("utf8") !== doc) fail("ถอดรหัสไฟล์ที่ build แล้วไม่ได้ผลเท่าเดิม");
// (probes contain a space or Thai, so they can never appear by chance inside the base64 text)
for (const probe of ["Premium Customer", "const Q =", "นิยาม KPI", "คำถามเก็บ Requirement"]) if (page.includes(probe)) fail("พบข้อความที่อ่านได้ในไฟล์ผลลัพธ์: " + probe);

await mkdir(OUT_DIR, {recursive:true});
await writeFile(OUT, page, "utf8");
await writeFile(path.join(OUT_DIR, ".nojekyll"), "", "utf8");
console.log("✓ เขียน " + path.relative(ROOT, OUT) + " (" + Math.round(page.length / 1024) + " KB)");
console.log("  ตัดส่วนที่ใช้ภายในทีมออก " + blocks + " ส่วน และโน้ตทีม " + notes + " ข้อ");
console.log("  push ได้เฉพาะโฟลเดอร์ docs/ — อย่า commit src/ หรือ exports/");
