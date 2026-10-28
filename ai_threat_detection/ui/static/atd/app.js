// Console behaviors (ES module, no third-party code, no network beyond same-origin JSON).

function confirmForms() {
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (ev) => {
      if (!window.confirm(form.dataset.confirm)) ev.preventDefault();
    });
  });
}

const SVG_NS = "http://www.w3.org/2000/svg";
function el(name, attrs = {}, text) {
  const n = document.createElementNS(SVG_NS, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, String(v));
  if (text !== undefined) n.textContent = text;
  return n;
}

// Grouped horizontal bars of metric values in [0, 1]; null => "N/A" (never drawn as 0 or 100%).
function renderBars(container) {
  const src = document.getElementById(container.dataset.source);
  if (!src) return;
  let rows;
  try { rows = JSON.parse(src.textContent); } catch { return; }
  if (!Array.isArray(rows) || rows.length === 0) {
    container.textContent = "Chưa có dữ liệu đánh giá.";
    return;
  }
  const methods = ["rules_only", "ml_only", "hybrid_or"];
  const colors = { rules_only: "#6b7a8f", ml_only: "#1f5fae", hybrid_or: "#8a4b00" };
  const rowH = 16, groupGap = 14, left = 190, width = 720, barMax = width - left - 70;
  const height = rows.length * (methods.length * rowH + groupGap) + 40;
  const svg = el("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", "aria-label": container.dataset.label || "chart" });
  let y = 10;
  for (const row of rows) {
    svg.appendChild(el("text", { x: 0, y: y + rowH, "font-weight": 600 }, row.label));
    for (const m of methods) {
      const v = row.values ? row.values[m] : null;
      svg.appendChild(el("text", { x: left - 80, y: y + rowH - 4 }, m));
      if (v === null || v === undefined) {
        svg.appendChild(el("text", { x: left + 4, y: y + rowH - 4 }, "N/A"));
      } else {
        const w = Math.max(1, Math.round(barMax * v));
        svg.appendChild(el("rect", { x: left, y: y + 2, width: w, height: rowH - 4, fill: colors[m] }));
        svg.appendChild(el("text", { x: left + w + 4, y: y + rowH - 4 }, v.toFixed(3)));
      }
      y += rowH;
    }
    y += groupGap;
  }
  svg.appendChild(el("text", { x: left, y: height - 8 }, container.dataset.axis || "F1 (0–1), N/A = không xác định"));
  container.replaceChildren(svg);
}

async function pollJobs() {
  const cells = [...document.querySelectorAll("[data-job-id][data-active='1']")];
  if (cells.length === 0) return;
  const ids = cells.map((c) => c.dataset.jobId).join(",");
  try {
    const resp = await fetch(`/jobs/status.json?ids=${encodeURIComponent(ids)}`, { credentials: "same-origin" });
    if (!resp.ok) return;
    const data = await resp.json();
    for (const c of cells) {
      const j = data.jobs[c.dataset.jobId];
      if (!j) continue;
      c.textContent = j.status;
      if (!["QUEUED", "RUNNING", "CANCEL_REQUESTED"].includes(j.status)) c.dataset.active = "0";
    }
  } catch { /* offline/stale: keep last known state */ }
  setTimeout(pollJobs, 3000);
}

confirmForms();
document.querySelectorAll("[data-chart='bars']").forEach(renderBars);
setTimeout(pollJobs, 3000);
