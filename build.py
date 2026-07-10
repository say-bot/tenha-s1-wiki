#!/usr/bin/env python3
"""시즌1 동맹 지휘부 위키 암호화 빌드 스크립트.

source.html의 img/*.webp 참조를 base64 데이터 URI로 인라인한 뒤,
AES-256-GCM으로 암호화해 암호 게이트가 달린 index.html을 생성한다.
(cheonha-archive/encrypt.py와 동일한 포맷 — 브라우저 Web Crypto로 복호화)

사용법:
    CHEONHA_PW='암호' python build.py            # source.html -> index.html
"""
import os, sys, re, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITERATIONS = 200_000
SRC = sys.argv[1] if len(sys.argv) > 1 else "source.html"
OUT = sys.argv[2] if len(sys.argv) > 2 else "index.html"

pw = os.environ.get("CHEONHA_PW")
if not pw:
    sys.exit("환경변수 CHEONHA_PW 에 암호를 넣어주세요.")

raw = open(SRC, encoding="utf-8").read()

# ---- 이미지 인라인 ----
missing = []
def inline(m):
    path = m.group(1)
    if not os.path.exists(path):
        missing.append(path)
        return m.group(0)
    data = base64.b64encode(open(path, "rb").read()).decode()
    return 'src="data:image/webp;base64,' + data + '"'

full, n = re.subn(r'src="(img/[^"]+\.webp)"', inline, raw)
if missing:
    sys.exit(f"이미지 파일 누락: {missing}")
print(f"이미지 {n}장 인라인 완료 (평문 {len(full):,} bytes)")

# ---- 암호화 ----
salt = os.urandom(16)
iv = os.urandom(12)
key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                 iterations=ITERATIONS).derive(pw.encode("utf-8"))
ct = AESGCM(key).encrypt(iv, full.encode("utf-8"), None)

payload = json.dumps({
    "salt": base64.b64encode(salt).decode(),
    "iv":   base64.b64encode(iv).decode(),
    "ct":   base64.b64encode(ct).decode(),
    "it":   ITERATIONS,
}, separators=(",", ":"))

GATE = '''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>시즌1 지휘부 위키 · 잠금</title>
<style>
  :root{color-scheme:dark;}
  *{box-sizing:border-box;}
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#141009;
    font-family:"Apple SD Gothic Neo","Pretendard","Malgun Gothic",system-ui,sans-serif;color:#e8e0d0;
    background-image:radial-gradient(120% 80% at 80% -10%,rgba(201,160,78,.10),transparent 60%),
      radial-gradient(90% 60% at -5% 5%,rgba(221,86,72,.06),transparent 55%);}
  .card{width:min(90vw,380px);padding:34px 30px 30px;border:1px solid #3a3122;border-radius:18px;
    background:rgba(36,29,19,.88);box-shadow:0 24px 60px rgba(0,0,0,.5);text-align:center;}
  .seal{width:54px;height:54px;margin:0 auto 16px;display:grid;place-items:center;font-size:24px;
    border:1px solid #6b5526;border-radius:13px;background:#2a2214;}
  h1{margin:0 0 6px;font-family:"Nanum Myeongjo","AppleMyungjo",Batang,serif;font-size:22px;letter-spacing:-.01em;color:#e8c87c;}
  p{margin:0 0 20px;color:#a89b82;font-size:13px;letter-spacing:.02em;}
  form{display:flex;gap:8px;}
  input{flex:1;min-width:0;padding:11px 13px;border:1px solid #3a3122;border-radius:10px;background:#1c1710;
    color:#e8e0d0;font-size:15px;outline:none;}
  input:focus{border-color:#c9a04e;box-shadow:0 0 0 3px rgba(201,160,78,.15);}
  button{padding:11px 16px;border:1px solid #6b5526;border-radius:10px;background:#2a2214;color:#c9a04e;
    font-weight:700;font-size:14px;cursor:pointer;white-space:nowrap;}
  button:hover{background:#332a19;}
  .err{margin-top:14px;min-height:18px;font-size:12.5px;color:#dd5648;letter-spacing:.02em;}
  .foot{margin-top:18px;font-size:11px;color:#7a6f58;letter-spacing:.06em;font-family:ui-monospace,monospace;}
</style>
</head>
<body>
<main>
  <div class="card">
    <div class="seal">🔒</div>
    <h1>시즌1 지휘부 위키</h1>
    <p>낙월 동맹 전용 · 암호를 입력하세요</p>
    <form id="f">
      <input id="pw" type="password" autocomplete="current-password" placeholder="암호" autofocus>
      <button type="submit">열기</button>
    </form>
    <div class="err" id="err"></div>
    <div class="foot">AES-256-GCM · 암호 없이는 열람 불가</div>
  </div>
</main>
<script id="payload" type="application/json">__PAYLOAD__</script>
<script>
(function(){
  var P=JSON.parse(document.getElementById('payload').textContent);
  var b64d=function(s){return Uint8Array.from(atob(s),function(c){return c.charCodeAt(0);});};
  var f=document.getElementById('f'),pw=document.getElementById('pw'),err=document.getElementById('err'),btn=f.querySelector('button');
  function unlock(secret){
    btn.disabled=true; btn.textContent='여는 중…';
    var enc=new TextEncoder();
    return crypto.subtle.importKey('raw',enc.encode(secret),'PBKDF2',false,['deriveKey'])
    .then(function(km){
      return crypto.subtle.deriveKey(
        {name:'PBKDF2',salt:b64d(P.salt),iterations:P.it,hash:'SHA-256'},
        km,{name:'AES-GCM',length:256},false,['decrypt']);
    })
    .then(function(key){
      return crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(P.iv)},key,b64d(P.ct));
    })
    .then(function(buf){
      var html=new TextDecoder().decode(buf);
      document.open(); document.write(html); document.close();
    });
  }
  f.addEventListener('submit',function(e){
    e.preventDefault(); err.textContent='';
    unlock(pw.value).catch(function(){
      err.textContent='암호가 올바르지 않습니다.'; btn.disabled=false; btn.textContent='열기'; pw.select();
    });
  });
  /* 아카이브 등 신뢰된 페이지에서 #k=암호 로 열면 자동 해제 */
  var m=(location.hash||'').match(/[#&]k=([^&]*)/);
  if(m){
    unlock(decodeURIComponent(m[1])).catch(function(){
      btn.disabled=false; btn.textContent='열기';
    });
  }
})();
</script>
</body>
</html>
'''

open(OUT, "w", encoding="utf-8").write(GATE.replace("__PAYLOAD__", payload))
print(f"OK  {SRC} -> {OUT}  (ciphertext {len(ct):,} bytes)")
