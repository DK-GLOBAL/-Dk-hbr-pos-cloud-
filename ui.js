/* DK HBR POS - replaces leftover emoji with the same line icons used in HR. Loaded after hr.js. */
(function () {
  const ic = window.DKI; if (!ic) return;
  const MAP = { "💳": "card", "🛡️": "shield", "🛡": "shield", "📶": "wifi", "📦": "package", "📞": "phone", "🧾": "receipt", "🍽️": "utensils", "🍽": "utensils", "🏨": "building", "⚙️": "gear", "⚙": "gear", "📅": "calendar", "🔐": "lock", "📥": "download", "💬": "message", "🎯": "target", "🤖": "bot", "🔗": "link", "🛏️": "bed", "🛏": "bed", "🍸": "wine", "💆": "sparkles", "🎉": "users", "🚖": "car", "📄": "file-text", "📊": "chart", "👥": "users", "⚠️": "alert", "⚠": "alert", "⛔": "ban", "✅": "check", "👤": "user", "🧩": "grid", "🔒": "lock", "➕": "plus", "✕": "x", "👁": "eye" };
  const RX = new RegExp(Object.keys(MAP).sort((a, b) => b.length - a.length).join("|"), "g"), SKIP = /^(SCRIPT|STYLE|TEXTAREA|INPUT|SELECT|OPTION|TITLE)$/;
  function swap(root) {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT), hit = [];
    for (let n; (n = w.nextNode());) { const p = n.parentNode; if (!p || SKIP.test(p.nodeName) || p.closest("#rcpt,.aim,.paper,.dkic")) continue; RX.lastIndex = 0; if (RX.test(n.nodeValue)) hit.push(n); }
    hit.forEach(n => { const f = document.createDocumentFragment(); let last = 0; n.nodeValue.replace(RX, (m, i) => { f.append(n.nodeValue.slice(last, i)); const s = document.createElement("span"); s.className = "dkic"; s.innerHTML = ic(MAP[m], 18); f.append(s); last = i + m.length; }); f.append(n.nodeValue.slice(last)); n.replaceWith(f); });
  }
  let t = 0; const run = () => { clearTimeout(t); t = setTimeout(() => { ["land", "app", "lg"].forEach(i => { const e = document.getElementById(i); if (e) swap(e); }); }, 40); };
  new MutationObserver(run).observe(document.body, { childList: true, subtree: true, characterData: true }); run();
})();
