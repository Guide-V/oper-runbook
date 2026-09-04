"""Shared look and feel for every self-contained HTML report mongoops produces.

One stylesheet (MongoDB palette) and one small script (table text filter + click-to-sort) so the
regex dashboard and the WAF scorecard read as one tool. No external assets: the pages must open
from a ticket attachment or an air-gapped jump host.
"""

from __future__ import annotations

# MongoDB brand palette, green-and-white: Spring Green #00ED64 (accent), Forest Green #00684A
# (headings, chips, PASS), Evergreen #023430 (header, dark text), Mist #E3FCF7 (table heads,
# soft fills), white page. Red and amber are kept for FAIL/WARN only: status semantics, not chrome.
BASE_CSS = """
:root{--green:#00ED64;--forest:#00684A;--evergreen:#023430;--mist:#E3FCF7;--mist2:#C0FAE6;
--ink:#023430;--grey:#5C6C75;--line:#C0FAE6;--bg:#FFFFFF;--panel:#F7FDFA;
--ok:#00684A;--warn:#C27C13;--bad:#DB3030;}
*{box-sizing:border-box}body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",
Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg)}
header{background:var(--evergreen);color:#fff;padding:22px 32px;
border-bottom:5px solid var(--green)}
header h1{margin:0 0 4px;font-size:22px;font-weight:600}header h1 code{color:var(--green);
background:transparent}
header .sub{color:var(--mist);font-size:13px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{background:var(--forest);border:1px solid #0B8A64;border-radius:6px;padding:4px 10px;
font-size:12px;color:#fff}.chip b{color:var(--green);font-weight:600;margin-right:6px}
main{padding:24px 32px;max-width:1600px;margin:0 auto}
section{margin-bottom:28px}h2{font-size:15px;margin:0 0 10px;color:var(--forest);
text-transform:uppercase;letter-spacing:.04em;border-left:4px solid var(--green);padding-left:8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.kpi .v{font-size:28px;font-weight:600;color:var(--evergreen)}
.kpi .l{font-size:12px;color:var(--grey)}
.kpi.alert .v{color:var(--bad)}.kpi.good .v{color:var(--ok)}
.bars{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px 16px}
.bar{display:grid;grid-template-columns:170px 1fr 60px;align-items:center;gap:12px;margin:6px 0}
.bar .track{background:var(--mist);border-radius:4px;height:14px;overflow:hidden}
.bar .fill{height:100%;border-radius:4px}.bar .n{text-align:right;font-variant-numeric:tabular-nums}
.fill.ok{background:var(--ok)}.fill.warn{background:var(--warn)}.fill.bad{background:var(--bad)}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);
border-radius:8px;overflow:hidden;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--mist);text-align:left;vertical-align:top}
th{background:var(--mist);color:var(--evergreen);font-weight:600;white-space:nowrap;cursor:pointer;
user-select:none}th:hover{background:var(--mist2)}tr:last-child td{border-bottom:0}
tbody tr:hover td{background:var(--panel)}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.nowrap{white-space:nowrap}td.nowrap code{word-break:normal}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--mist);
color:var(--evergreen);padding:1px 5px;border-radius:4px;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;
color:#fff;white-space:nowrap}.badge.ok{background:var(--ok)}.badge.warn{background:var(--warn)}
.badge.bad{background:var(--bad)}.badge.muted{background:var(--grey)}
.badge.index{background:var(--evergreen)}
.badge.search{background:var(--green);color:var(--evergreen)}
.kpi.search .v{color:var(--forest)}.kpi.index .v{color:var(--evergreen)}
.kpi.warn .v{color:var(--warn)}
.todo{display:grid;gap:10px}.todo .card{background:#fff;border:1px solid var(--line);
border-radius:8px;padding:12px 16px;border-left:5px solid var(--grey)}
.todo .card.search{border-left-color:var(--green)}
.todo .card.index{border-left-color:var(--evergreen)}
.todo .card.ok{border-left-color:var(--forest)}
.todo .card.warn{border-left-color:var(--warn)}.todo .card.bad{border-left-color:var(--bad)}
.todo h3{margin:0 0 6px;font-size:14px}.todo h3 .n{color:var(--grey);font-weight:400;
margin-left:8px}.todo ul{margin:0;padding-left:18px}.todo li{margin:4px 0}
.todo li code{margin-right:4px}.note{color:var(--grey);font-size:12px;margin-top:8px}
.plan-collscan{color:var(--bad);font-weight:600}
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:8px}
.toolbar input{flex:1;max-width:420px;padding:7px 10px;border:1px solid var(--line);
border-radius:6px;font-size:13px}.toolbar input:focus{outline:2px solid var(--green)}
.toolbar .count{color:var(--grey);font-size:12px}
.empty{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:28px;
text-align:center;color:var(--forest);font-size:16px}
.legend{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:8px}
.legend div{background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 12px;
font-size:12px}.legend .badge{margin-right:8px}
footer{padding:16px 32px;color:var(--grey);font-size:12px;border-top:4px solid var(--green);
background:var(--panel)}
a{color:var(--forest)}
"""

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
