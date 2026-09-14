"""Shared look and feel for every self-contained HTML report mongoops produces.

One stylesheet (MongoDB palette) and one small script (table text filter + click-to-sort) so the
regex dashboard and the WAF scorecard read as one tool. No external assets: the pages must open
from a ticket attachment or an air-gapped jump host.
"""

from __future__ import annotations

# MongoDB brand palette, green-and-white: Spring Green #00ED64 (accent, glow, meters), Forest
# Green #00684A (headings, PASS, links), Evergreen #023430 (header, dark text), Mist #E3FCF7 and
# #C0FAE6 (soft fills, borders), white page. Red and amber are kept for FAIL/WARN only: status
# semantics, never chrome. No web fonts or external assets, so the page opens anywhere.
BASE_CSS = """
:root{--green:#00ED64;--green2:#71F6BA;--forest:#00684A;--evergreen:#023430;--deep:#001E2B;
--mist:#E3FCF7;--mist2:#C0FAE6;--ink:#001E2B;--grey:#5C6C75;--line:#C0FAE6;--bg:#FFFFFF;
--panel:#F9FBFA;--ok:#00684A;--warn:#C27C13;--bad:#DB3030;--r:12px;
--shadow:0 1px 2px rgba(0,30,43,.06),0 4px 14px rgba(0,104,74,.08)}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,
sans-serif;color:var(--ink);background:var(--bg)}
header{position:relative;overflow:hidden;color:#fff;padding:28px 32px 24px;
background:linear-gradient(120deg,var(--deep) 0%,var(--evergreen) 55%,var(--forest) 100%);
border-bottom:5px solid var(--green)}
header:before{content:"";position:absolute;right:-120px;top:-160px;width:420px;height:420px;
border-radius:50%;background:radial-gradient(circle,rgba(0,237,100,.35),rgba(0,237,100,0) 65%);
pointer-events:none}
header:after{content:"";position:absolute;left:38%;bottom:-220px;width:360px;height:360px;
border-radius:50%;background:radial-gradient(circle,rgba(113,246,186,.18),rgba(0,0,0,0) 65%);
pointer-events:none}
header>*{position:relative}
header .brand{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:700;
letter-spacing:.14em;text-transform:uppercase;color:var(--green);margin-bottom:10px}
header .brand i{display:inline-block;width:10px;height:10px;border-radius:50% 50% 50% 0;
background:var(--green);transform:rotate(-45deg);box-shadow:0 0 12px rgba(0,237,100,.8)}
header h1{margin:0 0 6px;font-size:24px;font-weight:600;letter-spacing:-.01em}
header h1 code{color:var(--green);background:transparent;font-size:20px;padding:0}
header .sub{color:var(--mist2);font-size:13px;max-width:900px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.chip{background:rgba(255,255,255,.08);border:1px solid rgba(113,246,186,.35);border-radius:999px;
padding:4px 12px;font-size:12px;color:#fff;backdrop-filter:blur(2px)}
.chip b{color:var(--green);font-weight:600;margin-right:6px}
main{padding:28px 32px;max-width:1600px;margin:0 auto}
section{margin-bottom:32px}
h2{display:flex;align-items:center;gap:10px;font-size:13px;margin:0 0 12px;color:var(--forest);
text-transform:uppercase;letter-spacing:.08em;font-weight:700}
h2:before{content:"";width:6px;height:18px;border-radius:3px;background:var(--green)}
h2:after{content:"";flex:1;height:1px;background:var(--line)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.kpi{background:#fff;border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;
box-shadow:var(--shadow);border-top:3px solid var(--mist2)}
.kpi .v{font-size:30px;font-weight:700;color:var(--evergreen);font-variant-numeric:tabular-nums;
line-height:1.1}
.kpi .l{font-size:12px;color:var(--grey);margin-top:2px}
.kpi.alert{border-top-color:var(--bad)}.kpi.alert .v{color:var(--bad)}
.kpi.good{border-top-color:var(--green)}.kpi.good .v{color:var(--ok)}
.kpi.warn{border-top-color:var(--warn)}.kpi.warn .v{color:var(--warn)}
.kpi.search{border-top-color:var(--green2)}.kpi.search .v{color:var(--forest)}
.kpi.index{border-top-color:var(--evergreen)}.kpi.index .v{color:var(--evergreen)}
.bars{background:#fff;border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;
box-shadow:var(--shadow)}
.bar{display:grid;grid-template-columns:170px 1fr 60px;align-items:center;gap:12px;margin:6px 0}
.bar .track{background:var(--mist);border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;border-radius:4px}.bar .n{text-align:right;font-variant-numeric:tabular-nums}
.fill.ok{background:var(--ok)}.fill.warn{background:var(--warn)}.fill.bad{background:var(--bad)}
table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;
border:1px solid var(--line);border-radius:var(--r);overflow:hidden;font-size:13px;
box-shadow:var(--shadow)}
th,td{padding:9px 12px;border-bottom:1px solid var(--mist);text-align:left;vertical-align:top}
th{background:var(--mist);color:var(--evergreen);font-weight:600;white-space:nowrap;cursor:pointer;
user-select:none;font-size:12px;letter-spacing:.02em}th:hover{background:var(--mist2)}
tr:last-child td{border-bottom:0}tbody tr:hover td{background:var(--panel)}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.nowrap{white-space:nowrap}td.nowrap code{word-break:normal}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--mist);
color:var(--evergreen);padding:1px 6px;border-radius:5px;word-break:break-all}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11px;font-weight:700;
letter-spacing:.02em;color:#fff;white-space:nowrap}
.badge.ok{background:var(--ok)}.badge.warn{background:var(--warn)}
.badge.bad{background:var(--bad)}.badge.muted{background:var(--grey)}
.badge.index{background:var(--evergreen)}
.badge.search{background:var(--green);color:var(--deep)}
.todo{display:grid;gap:10px}.todo .card{background:#fff;border:1px solid var(--line);
border-radius:var(--r);padding:14px 18px;border-left:5px solid var(--grey);box-shadow:var(--shadow)}
.todo .card.search{border-left-color:var(--green)}
.todo .card.index{border-left-color:var(--evergreen)}
.todo .card.ok{border-left-color:var(--forest)}
.todo .card.warn{border-left-color:var(--warn)}.todo .card.bad{border-left-color:var(--bad)}
.todo h3{margin:0 0 6px;font-size:14px}.todo h3 .n{color:var(--grey);font-weight:400;
margin-left:8px}.todo ul{margin:0;padding-left:18px}.todo li{margin:4px 0}
.todo li code{margin-right:4px}.note{color:var(--grey);font-size:12px;margin-top:8px}
.plan-collscan{color:var(--bad);font-weight:600}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:10px}
.toolbar input{flex:1;max-width:420px;padding:8px 12px;border:1px solid var(--line);
border-radius:999px;font-size:13px;background:#fff}
.toolbar input:focus{outline:2px solid var(--green);outline-offset:1px}
.toolbar .count{color:var(--grey);font-size:12px}
.empty{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:28px;
text-align:center;color:var(--forest);font-size:16px}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:8px}
.legend div{background:#fff;border:1px solid var(--line);border-radius:var(--r);padding:10px 12px;
font-size:12px}.legend .badge{margin-right:8px}
footer{padding:18px 32px;color:var(--grey);font-size:12px;border-top:4px solid var(--green);
background:var(--evergreen);color:var(--mist2)}footer a{color:var(--green)}
footer code{background:rgba(255,255,255,.1);color:var(--green2)}
footer .harbour{margin-top:12px;padding-top:10px;border-top:1px solid rgba(113,246,186,.25);
color:var(--mist2);font-size:11px;letter-spacing:.02em}
a{color:var(--forest)}
@media (max-width:720px){header,main,footer{padding-left:16px;padding-right:16px}
.bar{grid-template-columns:110px 1fr 50px}}
"""

# Safe-harbour line at the bottom of every page: the tool reads the customer's Atlas
# configuration and gives an opinion; it is not a MongoDB product and carries no support.
SAFE_HARBOUR_HTML = (
    '<div class="harbour">Made by GuideV. Not an officially supported MongoDB tool. '
    "The score and findings are advisory; verify them against the official documentation "
    "before making changes.</div>"
)

# Text filter over the table with id="findings" and click-to-sort on its headers. Harmless when
# the page has no such table.
TABLE_JS = """
(function(){
  var input=document.getElementById('flt'),table=document.getElementById('findings');
  if(!table)return;
  var rows=Array.prototype.slice.call(table.tBodies[0].rows),count=document.getElementById('cnt');
  function apply(){
    var q=(input.value||'').toLowerCase(),shown=0;
    rows.forEach(function(r){var hit=!q||r.textContent.toLowerCase().indexOf(q)>=0;
      r.style.display=hit?'':'none';if(hit)shown++;});
    count.textContent=shown+' of '+rows.length+' shown';
  }
  input.addEventListener('input',apply);apply();
  var ths=table.tHead.rows[0].cells;
  Array.prototype.forEach.call(ths,function(th,i){
    th.addEventListener('click',function(){
      var asc=th.getAttribute('data-asc')!=='1';
      Array.prototype.forEach.call(ths,function(t){t.removeAttribute('data-asc');});
      th.setAttribute('data-asc',asc?'1':'0');
      var num=th.classList.contains('num');
      rows.sort(function(a,b){
        var x=a.cells[i].textContent,y=b.cells[i].textContent;
        if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return asc?x-y:y-x;}
        return asc?x.localeCompare(y):y.localeCompare(x);
      });
      rows.forEach(function(r){table.tBodies[0].appendChild(r);});
    });
  });
})();
"""
