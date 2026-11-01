"use strict";
const $ = s => document.querySelector(s), $$ = s => [...document.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const cls = l => l.split(" ")[0].toLowerCase();
const COLORS = {low: "var(--low)", moderate: "var(--moderate)", high: "var(--high)", critical: "var(--critical)"};
const TITLES = {dash: "Dashboard", analyze: "Analyze Message", history: "History", guide: "Threat Guide", about: "About"};
const EX = [
 ["Bank suspension", "Dear Customer, your HDFC Bank account has been suspended due to unusual activity. Verify your login credentials immediately: http://hdfcbank-secure-login.top/verify to avoid permanent closure. Act now."],
 ["Parcel SMS", "DHL: Your parcel could not be delivered. Pay a small redelivery fee of Rs 25 at http://bit.ly/dhl-redeliver within 12 hours or it will be returned."],
 ["Job offer", "Congratulations! You are selected for a Work-From-Home role at TechNova. Salary Rs 60,000/month. Pay a refundable registration fee of Rs 1,500 to confirm your seat and reply with your bank details and Aadhaar number."],
 ["Prize winner", "You have won a free gift! Claim your prize now: http://45.33.12.9/claim - exclusive reward, expires today."],
 ["Password reset (subtle)", "Hi, we received a request to reset your Microsoft account password. If this was you, confirm your login here: https://account.microsoft-support.xyz/reset . If not, ignore this email."],
 ["Legitimate notification", "Hi Asha, your order #48213 has shipped and will arrive by Friday. Track it at https://www.amazon.com/your-orders. We will never ask for your password or OTP. Thanks for shopping with us."]];
let current = null;

function show(view) {
  $$(".view").forEach(v => v.hidden = v.id !== "v-" + view);
  $$("nav button").forEach(b => b.classList.toggle("on", b.dataset.view === view));
  $("#title").textContent = TITLES[view];
  if (view === "dash") renderDash(); if (view === "history") renderHist();
}
const loadEx = i => { $("#msg").value = EX[i][1]; count(); show("analyze"); $("#result").innerHTML = ""; };
const count = () => $("#count").textContent = $("#msg").value.length;
const getHist = () => { try { return JSON.parse(localStorage.getItem("pg_history") || "[]"); } catch (e) { return []; } };
const setHist = h => { try { localStorage.setItem("pg_history", JSON.stringify(h.slice(0, 25))); } catch (e) {} };

async function analyze() {
  const msg = $("#msg").value; $("#err").textContent = "";
  if (!msg.trim()) { $("#err").textContent = "Please paste a message first."; return; }
  $("#loader").hidden = false; $("#analyze").disabled = true;
  try {
    const [res] = await Promise.all([fetch("/api/analyze", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({message: msg})}), new Promise(r => setTimeout(r, 600))]);
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || "Request failed.");
    setHist([{t: d.analyzed_at, preview: d.preview.slice(0, 60), score: d.score, level: d.level, result: d}, ...getHist()]);
    render(d);
  } catch (e) { $("#err").textContent = e.message === "Failed to fetch" ? "Cannot reach the server. Is app.py running?" : e.message; }
  finally { $("#loader").hidden = true; $("#analyze").disabled = false; }
}

function render(d) {
  current = d; const c = cls(d.level);
  const table = (heads, rows) => rows.length ? `<div class="wrap"><table><tr>${heads.map(h => `<th>${h}</th>`).join("")}</tr>${rows.join("")}</table></div>` : '<p class="muted">None detected.</p>';
  $("#result").innerHTML = `
  <div class="card"><div class="hero"><div class="ring" style="--c:${COLORS[c]};--p:${d.score}"><span>${d.score}</span></div>
   <div><span class="badge ${c}">${esc(d.level)}</span><p>${esc(d.summary)}</p><p class="muted">${esc(d.explanation)}</p></div></div>
   <div class="row acts"><button class="btn" id="b-copy">Copy report</button><button class="btn ghost" id="b-txt">Download TXT</button><button class="btn ghost" id="b-json">Download JSON</button></div></div>
  <div class="card"><h2>Score breakdown</h2>${table(["Source", "Indicator", "Points", ""], d.breakdown.map(b => `<tr><td>${esc(b.source)}</td><td>${esc(b.label)}</td><td>+${b.points}</td><td><div class="bar"><i style="width:${Math.min(100, b.points * 2.5)}%"></i></div></td></tr>`))}
   <ul class="muted">${d.method.map(m => `<li>${esc(m)}</li>`).join("")}</ul></div>
  <div class="card"><h2>Suspicious phrases</h2>${table(["Phrase", "Category", "Why suspicious", "Risk"], d.keywords.map(k => `<tr><td><code>${esc(k.phrase)}</code></td><td>${esc(k.category)}</td><td>${esc(k.why)}</td><td>+${k.points}</td></tr>`))}</div>
  <div class="card"><h2>URL analysis</h2>${table(["URL", "Domain", "Indicators", "Risk", "Explanation"], d.urls.map(u => `<tr><td><code>${esc(u.url)}</code></td><td>${esc(u.domain)}</td><td>${u.indicators.map(i => esc(i.label)).join("<br>") || "–"}</td><td><span class="badge ${u.risk_level.toLowerCase()}">${esc(u.risk_level)}</span></td><td>${esc(u.explanation)}</td></tr>`))}</div>
  <div class="card"><h2>Social engineering indicators</h2>${table(["Technique", "Evidence", "Why it matters"], d.social_engineering.map(t => `<tr><td>${esc(t.technique)}</td><td><code>${esc(t.evidence)}</code></td><td>${esc(t.why)}</td></tr>`))}</div>
  <div class="card"><h2>Red flags</h2>${d.red_flags.length ? `<ul>${d.red_flags.map(f => `<li>${esc(f)}</li>`).join("")}</ul>` : '<p class="muted">No red flags found.</p>'}</div>
  <div class="card"><h2>Recommended actions</h2><ul>${d.recommendations.map(r => `<li>${esc(r)}</li>`).join("")}</ul><p class="muted">${esc(d.disclaimer)}</p></div>`;
  $("#b-copy").onclick = async e => { try { await navigator.clipboard.writeText(d.report_text); e.target.textContent = "Copied ✓"; } catch (x) { e.target.textContent = "Copy blocked by browser"; } };
  $("#b-txt").onclick = () => save(d.report_text, "text/plain", "txt");
  $("#b-json").onclick = () => { const {report_text, ...rest} = d; save(JSON.stringify(rest, null, 2), "application/json", "json"); };
  $("#result").scrollIntoView({behavior: "smooth"});
}
function save(content, type, ext) {
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], {type}));
  a.download = "phishguard-report." + ext; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function renderDash() {
  const h = getHist(), n = h.length;
  $("#s-total").textContent = n; $("#s-avg").textContent = n ? Math.round(h.reduce((a, x) => a + x.score, 0) / n) : 0; $("#s-max").textContent = n ? Math.max(...h.map(x => x.score)) : 0;
  $("#dist").innerHTML = ["Low Risk", "Moderate Risk", "High Risk", "Critical Risk"].map(l => {
    const k = h.filter(x => x.level === l).length;
    return `<div class="dist"><span>${l}</span><div class="bar"><i style="width:${n ? k / n * 100 : 0}%;background:${COLORS[cls(l)]}"></i></div><b>${k}</b></div>`; }).join("");
}
function renderHist() {
  const h = getHist();
  $("#hist").innerHTML = h.length ? h.map((x, i) => `<div class="hist-item"><div><code>${esc(x.preview)}…</code><div class="muted">${esc(x.t)}</div></div><div><span class="badge ${cls(x.level)}">${x.score} · ${esc(x.level)}</span> <button class="btn ghost" data-i="${i}">Open</button></div></div>`).join("") : '<p class="muted">No analyses yet.</p>';
  $$("#hist [data-i]").forEach(b => b.onclick = () => { show("analyze"); render(h[b.dataset.i].result); });
}
$$("nav button").forEach(b => b.onclick = () => show(b.dataset.view));
["#ex", "#ex-dash"].forEach(s => $(s).innerHTML = EX.map((e, i) => `<button data-e="${i}">${esc(e[0])}</button>`).join(""));
$$("[data-e]").forEach(b => b.onclick = () => loadEx(+b.dataset.e));
$("#msg").oninput = count; $("#analyze").onclick = analyze;
$("#clear").onclick = () => { $("#msg").value = ""; $("#result").innerHTML = ""; $("#err").textContent = ""; count(); };
$("#clear-hist").onclick = () => { setHist([]); renderHist(); };
show("dash");
