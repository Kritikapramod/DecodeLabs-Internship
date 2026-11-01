// Interface logic only. The password is sent to the local Python server for scoring
// and is never written to the page, console, or any storage.
const input = document.getElementById("pw");
const toggleButton = document.getElementById("toggle");
const COLORS = { Weak: "#ff5d73", Medium: "#fbbf24", Strong: "#34d399", Empty: "#233056" };
const CHECK_NAMES = { length: "At least 8 characters", uppercase: "Uppercase letter",
                      number: "Number", special: "Special character" };

// If the page was opened directly from disk, there is no server to talk to.
if (location.protocol === "file:") {
  document.getElementById("file-warning").hidden = false;
}

function fillList(listId, items) {
  const list = document.getElementById(listId);
  list.replaceChildren();                       // textContent only: no HTML injection
  items.forEach(([text, ok]) => {
    const li = document.createElement("li");
    li.textContent = text;
    if (ok) li.className = "ok";
    list.appendChild(li);
  });
}

function showResult(r) {
  document.getElementById("result").hidden = false;
  const label = document.getElementById("label");
  label.textContent = r.label;
  label.className = "result-badge " + r.label;
  document.getElementById("score").textContent =
    r.length ? `Score ${r.score} of ${r.max_score}` : "Nothing entered yet.";
  const bar = document.getElementById("bar");
  bar.style.width = (r.score / r.max_score) * 100 + "%";
  bar.style.background = r.label === "Weak" ? COLORS.Weak
    : r.label === "Medium" ? COLORS.Medium
    : r.label === "Strong" ? "linear-gradient(90deg,#22d3ee,#34d399)" : COLORS.Empty;
  document.querySelector(".meter").setAttribute("aria-valuenow", r.score);
  fillList("checklist", Object.entries(CHECK_NAMES).map(([k, t]) => [t, r.checks[k]]));
  fillList("tips", r.tips.length ? r.tips.map(t => [t, false]) : [["Nice work. No further suggestions.", false]]);
}

async function checkPassword() {
  try {
    const response = await fetch("/api/check", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: input.value })   // sent exactly as typed
    });
    if (!response.ok) throw new Error("Server error");
    showResult(await response.json());
  } catch (err) {
    alert("Could not check the password. Run 'python app.py' and open http://127.0.0.1:8000");
  }
}

document.getElementById("check").addEventListener("click", checkPassword);
input.addEventListener("keydown", e => { if (e.key === "Enter") checkPassword(); });

toggleButton.addEventListener("click", () => {
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  toggleButton.textContent = show ? "Hide" : "Show";
  toggleButton.setAttribute("aria-pressed", String(show));
  toggleButton.setAttribute("aria-label", show ? "Hide password" : "Show password");
});

document.getElementById("clear").addEventListener("click", () => {
  input.value = "";
  input.type = "password";
  toggleButton.textContent = "Show";
  document.getElementById("result").hidden = true;
  input.focus();
});
