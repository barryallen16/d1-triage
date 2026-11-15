

const NS = "http://www.w3.org/2000/svg";

const C_COS = Math.cos(Math.PI / 6);
const C_SIN = 0.5;
const SCALE = 1.30;
const ORIGIN_X = 450;
const ORIGIN_Y = 145;

function P(x, y, z = 0) {
  const sx = ORIGIN_X + SCALE * C_COS * (x - y);
  const sy = ORIGIN_Y + SCALE * C_SIN * (x + y) - z * SCALE * 0.95;
  return [sx, sy];
}

function mk(tag, attrs, parent) {
  const el = document.createElementNS(NS, tag);
  for (const k in attrs) el.setAttribute(k, String(attrs[k]));
  if (parent) parent.appendChild(el);
  return el;
}

function f(n) { return Math.round(n * 100) / 100; }
function line(pts) { return "M" + pts.map(p => f(p[0]) + " " + f(p[1])).join(" L "); }
function poly(pts) { return line(pts) + " Z"; }
function seg(p1, p2) { return `M ${f(p1[0])} ${f(p1[1])} L ${f(p2[0])} ${f(p2[1])}`; }

function rrect(x0, y0, x1, y1, r, n = 6) {
  r = Math.max(0, Math.min(r, (x1 - x0) / 2, (y1 - y0) / 2));
  const pts = [];
  const corners = [
    [x1 - r, y1 - r, 0],
    [x0 + r, y1 - r, 90],
    [x0 + r, y0 + r, 180],
    [x1 - r, y0 + r, 270]
  ];
  for (const [cx, cy, a0] of corners) {
    for (let i = 0; i <= n; i++) {
      const a = (a0 + (90 * i) / n) * (Math.PI / 180);
      pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
  }
  return pts;
}

function circ(cx, cy, r, n = 24) {
  const pts = [];
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2;
    pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
  }
  return pts;
}

function frontHalf(pts) {
  let minIdx = 0, maxIdx = 0;
  pts.forEach((p, i) => {
    if (p[0] < pts[minIdx][0]) minIdx = i;
    if (p[0] > pts[maxIdx][0]) maxIdx = i;
  });
  const walk = (a, b) => {
    const out = [];
    for (let i = a; ; i = (i + 1) % pts.length) {
      out.push(pts[i]);
      if (i === b) break;
    }
    return out;
  };
  const h1 = walk(minIdx, maxIdx);
  const h2 = walk(maxIdx, minIdx);
  const avg = h => h.reduce((s, p) => s + p[1], 0) / h.length;
  return avg(h1) > avg(h2) ? h1 : h2.reverse();
}

function createPrism(footPts, topPts) {
  const allScreen = topPts.concat(footPts);
  const n = allScreen.length;
  if (n < 3) return "";
  const sorted = allScreen.slice().sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const cross = (o, a, b) => (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0]);
  const lower = [];
  for (const p of sorted) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop();
    lower.push(p);
  }
  const upper = [];
  for (let i = sorted.length - 1; i >= 0; i--) {
    const p = sorted[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop();
    upper.push(p);
  }
  lower.pop();
  upper.pop();
  return poly(lower.concat(upper));
}

function mountTriagePipeline(hostElement, options = {}) {
  const onStageSelect = options.onStageSelect || (() => {});
  const theme = options.theme || "dark";

  hostElement.innerHTML = "";
  hostElement.setAttribute("data-hairline", "triage-pipeline");
  hostElement.setAttribute("data-hairline-theme", theme);
  hostElement.style.position = "relative";
  hostElement.style.width = "100%";
  hostElement.style.aspectRatio = "900 / 290";
  hostElement.style.userSelect = "none";
  hostElement.style.touchAction = "pan-y";

  const svg = mk("svg", {
    viewBox: "0 0 900 290",
    "aria-hidden": "true",
    style: "width:100%; height:100%; display:block;"
  }, hostElement);

  const styleEl = mk("style", {}, svg);
  styleEl.textContent = `
    path, polygon, ellipse, line, circle {
      vector-effect: non-scaling-stroke;
      stroke-linejoin: round;
      stroke-linecap: round;
    }
    .nf { fill: none !important; }
    .fo { stroke: none !important; }
    .g-ground path { fill: none; stroke: #153259; stroke-width: 1px; }
    .g-rails path.sil { fill: none; stroke: #60a5fa; stroke-width: 1.6px; }
    .g-rails path.lo { fill: none; stroke: #1e3f6f; stroke-width: 1.2px; }
    .station-node { cursor: pointer; }
    .station-node .sil { fill: #0b1e3d; stroke: #60a5fa; stroke-width: 1.6px; transition: fill 140ms ease, stroke 140ms ease; }
    .station-node:hover .sil { fill: #132a54; stroke: #93c5fd; }
    .station-node .sil.hi { fill: #221c3b !important; stroke: #fd91cc !important; stroke-width: 2.2px !important; filter: drop-shadow(0 0 8px rgba(253, 145, 204, 0.55)); }
    .station-node path.lo { fill: none; stroke: #38bdf8; stroke-width: 1.2px; }
    circle.dot { stroke: none; fill: #fd91cc; }
    circle.dot.m { stroke: none; fill: #38bdf8; }
    .packet-photon path.hi { fill: none; stroke: #fd91cc; stroke-width: 2.2px; }
    .packet-photon polygon.dot { fill: #ffffff; stroke: #fd91cc; stroke-width: 1.8px; filter: drop-shadow(0 0 6px #fd91cc); }
  `;

  const gGround = mk("g", { class: "g-ground" }, svg);
  const gRails = mk("g", { class: "g-rails" }, svg);
  const gStations = mk("g", { class: "g-stations" }, svg);
  const gPacket = mk("g", { class: "g-packet" }, svg);

  const STATIONS = [
    { id: 1, name: "Sink Grounding", x: -160, y: 0, w: 46, h: 40, r: 8, zThick: 8, title: "01 · Sink Grounding" },
    { id: 2, name: "Invariant Sieve", x: -50, y: 0, w: 44, h: 44, r: 22, zThick: 10, title: "02 · Invariant Sieve" },
    { id: 3, name: "d1-3B Inference Core", x: 60, y: 0, w: 52, h: 44, r: 10, zThick: 14, title: "03 · d1-3B Inference Core" },
    { id: 4, name: "Triage Fork", x: 175, y: 0, isFork: true, title: "04 · Deterministic Fork" }
  ];

  const FORK_SUPPRESS = { x: 175, y: -36, w: 38, h: 32, r: 7, zThick: 6, label: "Suppression Trap" };
  const FORK_DISPATCH = { x: 175, y: 36, w: 38, h: 32, r: 7, zThick: 6, label: "Dispatch Pad" };

  for (let gx = -240; gx <= 240; gx += 40) {
    mk("path", {
      d: seg(P(gx, -70, 0), P(gx, 70, 0)),
      class: "lo nf",
      style: "stroke-dasharray: 2 6; opacity: 0.3;"
    }, gGround);
  }
  for (let gy = -60; gy <= 60; gy += 30) {
    mk("path", {
      d: seg(P(-240, gy, 0), P(240, gy, 0)),
      class: "lo nf",
      style: "stroke-dasharray: 2 6; opacity: 0.3;"
    }, gGround);
  }

  const RW = 5;
  const railMainTop = mk("path", {
    d: `M ${f(P(-220, -RW, 0)[0])} ${f(P(-220, -RW, 0)[1])} L ${f(P(110, -RW, 0)[0])} ${f(P(110, -RW, 0)[1])}`,
    class: "sil nf",
    style: "stroke-width:1.2; opacity:0.8;"
  }, gRails);
  const railMainBot = mk("path", {
    d: `M ${f(P(-220, RW, 0)[0])} ${f(P(-220, RW, 0)[1])} L ${f(P(110, RW, 0)[0])} ${f(P(110, RW, 0)[1])}`,
    class: "sil nf",
    style: "stroke-width:1.2; opacity:0.8;"
  }, gRails);
  const railCenterGuide = mk("path", {
    d: `M ${f(P(-220, 0, 0)[0])} ${f(P(-220, 0, 0)[1])} L ${f(P(110, 0, 0)[0])} ${f(P(110, 0, 0)[1])}`,
    class: "lo nf",
    style: "stroke-dasharray: 4 4;"
  }, gRails);

  const pForkStart = P(110, 0, 0);
  const pForkCtrlUp = P(140, -25, 0);
  const pForkEndUp = P(175, -36, 0);
  const railForkUp = mk("path", {
    d: `M ${f(pForkStart[0])} ${f(pForkStart[1])} Q ${f(pForkCtrlUp[0])} ${f(pForkCtrlUp[1])} ${f(pForkEndUp[0])} ${f(pForkEndUp[1])}`,
    class: "lo nf",
    style: "stroke-dasharray: 3 3; stroke-width: 1.2;"
  }, gRails);

  const pForkCtrlDown = P(140, 25, 0);
  const pForkEndDown = P(175, 36, 0);
  const railForkDown = mk("path", {
    d: `M ${f(pForkStart[0])} ${f(pForkStart[1])} Q ${f(pForkCtrlDown[0])} ${f(pForkCtrlDown[1])} ${f(pForkEndDown[0])} ${f(pForkEndDown[1])}`,
    class: "sil nf",
    style: "stroke-width: 1.4;"
  }, gRails);

  const stationViews = [];

  {
    const st = STATIONS[0];
    const g = mk("g", { class: "station-node", id: "st-node-1" }, gStations);
    const drop = mk("path", { class: "lo nf", style: "stroke-dasharray: 2 3;" }, g);
    const sil = mk("path", { class: "sil" }, g);
    const crease = mk("path", { class: "lo nf" }, g);
    const detail = mk("path", { class: "lo nf" }, g);
    stationViews.push({ st, g, drop, sil, crease, detail, liftZ: 0, targetLift: 0 });
  }

  {
    const st = STATIONS[1];
    const g = mk("g", { class: "station-node", id: "st-node-2" }, gStations);
    const drop = mk("path", { class: "lo nf", style: "stroke-dasharray: 2 3;" }, g);
    const sil = mk("path", { class: "sil" }, g);
    const crease = mk("path", { class: "lo nf" }, g);
    const detail = mk("path", { class: "lo nf" }, g);
    stationViews.push({ st, g, drop, sil, crease, detail, liftZ: 0, targetLift: 0 });
  }

  {
    const st = STATIONS[2];
    const g = mk("g", { class: "station-node", id: "st-node-3" }, gStations);
    const drop = mk("path", { class: "lo nf", style: "stroke-dasharray: 2 3;" }, g);
    const sil = mk("path", { class: "sil" }, g);
    const crease = mk("path", { class: "lo nf" }, g);
    const detail = mk("path", { class: "lo nf" }, g);
    const pips = [];
    for (let k = 0; k < 8; k++) {
      pips.push(mk("circle", { r: 1.5, class: "dot m" }, g));
    }
    stationViews.push({ st, g, drop, sil, crease, detail, pips, liftZ: 0, targetLift: 0 });
  }

  {
    const st = STATIONS[3];
    const g = mk("g", { class: "station-node", id: "st-node-4" }, gStations);

    const dropA = mk("path", { class: "lo nf", style: "stroke-dasharray: 2 3;" }, g);
    const silA = mk("path", { class: "sil" }, g);
    const creaseA = mk("path", { class: "lo nf" }, g);

    const dropB = mk("path", { class: "lo nf", style: "stroke-dasharray: 2 3;" }, g);
    const silB = mk("path", { class: "sil" }, g);
    const creaseB = mk("path", { class: "lo nf" }, g);

    stationViews.push({
      st, g, isFork: true,
      forkA: { st: FORK_SUPPRESS, drop: dropA, sil: silA, crease: creaseA, liftZ: 0, targetLift: 0 },
      forkB: { st: FORK_DISPATCH, drop: dropB, sil: silB, crease: creaseB, liftZ: 0, targetLift: 0 }
    });
  }

  const packetG = mk("g", { class: "packet-photon" }, gPacket);
  const packetTrail = mk("path", { class: "hi nf", style: "stroke-width:1.8; opacity:0.85;" }, packetG);
  const packetBody = mk("polygon", { class: "dot", style: "filter:drop-shadow(0 0 4px var(--hl-hi));" }, packetG);

  let currentStage = 1;
  let activeScenario = "pt";
  let currentIsTp = true;
  let packetT = 0.15;
  let packetTargetT = 0.15;
  let isAutoPlay = false;
  let lastTime = performance.now();
  let rafId = 0;
  let isRunning = true;

  const STAGE_TRACK_POS = {
    1: 0.15,
    2: 0.40,
    3: 0.65,
    4: 0.95
  };

  function selectStage(stageNum, emit = true) {
    currentStage = Math.max(1, Math.min(4, stageNum));
    packetTargetT = STAGE_TRACK_POS[currentStage];

    stationViews.forEach((v, idx) => {
      const isSel = (idx + 1) === currentStage;
      if (v.isFork) {
        v.forkA.targetLift = (isSel && !currentIsTp) ? 14 : 0;
        v.forkB.targetLift = (isSel && currentIsTp) ? 14 : 0;
        v.forkA.sil.classList.toggle("hi", isSel && !currentIsTp);
        v.forkB.sil.classList.toggle("hi", isSel && currentIsTp);
      } else {
        v.targetLift = isSel ? 16 : 0;
        v.sil.classList.toggle("hi", isSel);
      }
    });

    if (emit) onStageSelect(currentStage);
  }

  function setVerdict(isTp) {
    currentIsTp = !!isTp;
    if (railForkUp && railForkDown) {
      if (currentIsTp) {
        railForkDown.classList.add("sil");
        railForkDown.classList.remove("lo");
        railForkUp.classList.add("lo");
        railForkUp.classList.remove("sil");
      } else {
        railForkUp.classList.add("sil");
        railForkUp.classList.remove("lo");
        railForkDown.classList.add("lo");
        railForkDown.classList.remove("sil");
      }
    }
    if (currentStage === 4) {
      selectStage(4, false);
    }
  }

  function setScenario(scenKey, isTpOverride = null) {
    activeScenario = scenKey;
    if (isTpOverride !== null) {
      setVerdict(isTpOverride);
    } else {
      setVerdict(activeScenario === "pt" || activeScenario === "cmdi");
    }
  }

  hostElement.addEventListener("mousemove", (e) => {
    if (isAutoPlay) return;
    const rect = hostElement.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (900 / rect.width);
    const my = (e.clientY - rect.top) * (320 / rect.height);

    let closestStage = -1;
    let minD = 55;

    [1, 2, 3].forEach(idx => {
      const st = STATIONS[idx - 1];
      const p = P(st.x, st.y, 0);
      const d = Math.hypot(mx - p[0], my - p[1]);
      if (d < minD) { minD = d; closestStage = idx; }
    });

    const pForkA = P(FORK_SUPPRESS.x, FORK_SUPPRESS.y, 0);
    const pForkB = P(FORK_DISPATCH.x, FORK_DISPATCH.y, 0);
    if (Math.hypot(mx - pForkA[0], my - pForkA[1]) < minD || Math.hypot(mx - pForkB[0], my - pForkB[1]) < minD) {
      closestStage = 4;
    }

    if (closestStage !== -1 && closestStage !== currentStage) {
      selectStage(closestStage, true);
    }
  });

  hostElement.addEventListener("click", () => {
    isAutoPlay = false;
  });

  function tick(now) {
    if (!isRunning) return;
    const dt = Math.min((now - lastTime) / 1000, 0.05);
    lastTime = now;

    packetT += (packetTargetT - packetT) * Math.min(dt * 8, 0.3);

    let pPkt = [0, 0];
    let pTrail = [0, 0];
    const isTp = currentIsTp;

    if (packetT <= 0.70) {
      const u = packetT / 0.70;
      const wx = -200 + u * 310;
      pPkt = P(wx, 0, 8);
      pTrail = P(wx - 18, 0, 8);
    } else {
      const u = (packetT - 0.70) / 0.30;
      const targetY = isTp ? 36 : -36;
      const wx = 110 + u * 65;
      const wy = u * targetY;
      pPkt = P(wx, wy, 8);
      pTrail = P(wx - 16, wy * 0.8, 8);
    }

    const pr = 4;
    const diamond = [
      [pPkt[0], pPkt[1] - pr * 1.2],
      [pPkt[0] + pr * 1.5, pPkt[1]],
      [pPkt[0], pPkt[1] + pr * 1.2],
      [pPkt[0] - pr * 1.5, pPkt[1]]
    ];
    packetBody.setAttribute("points", diamond.map(p => `${f(p[0])},${f(p[1])}`).join(" "));
    packetTrail.setAttribute("d", seg(pTrail, pPkt));

    const breath = Math.sin(now / 900) * 1.8;

    stationViews.forEach((v, idx) => {
      if (v.isFork) {
        v.forkA.liftZ += (v.forkA.targetLift - v.forkA.liftZ) * Math.min(dt * 9, 0.35);
        const zA = v.forkA.liftZ + (v.forkA.targetLift > 0 ? 0 : Math.sin(now / 900 + 1.2) * 1.2);
        renderStationPad(v.forkA, zA);

        v.forkB.liftZ += (v.forkB.targetLift - v.forkB.liftZ) * Math.min(dt * 9, 0.35);
        const zB = v.forkB.liftZ + (v.forkB.targetLift > 0 ? 0 : Math.sin(now / 900 + 1.4) * 1.2);
        renderStationPad(v.forkB, zB);
      } else {
        v.liftZ += (v.targetLift - v.liftZ) * Math.min(dt * 9, 0.35);
        const z = v.liftZ + (v.targetLift > 0 ? 0 : Math.sin(now / 900 + idx * 0.8) * 1.4);
        renderStation(v, idx, z);
      }
    });

    rafId = requestAnimationFrame(tick);
  }

  function renderStation(v, idx, zLift) {
    const st = v.st;
    const hw = st.w / 2, hh = st.h / 2;
    const r = st.r;
    const footRing = (idx === 1) ? circ(st.x, st.y, hw, 20) : rrect(st.x - hw, st.y - hh, st.x + hw, st.y + hh, r, 6);
    const foot = footRing.map(p => P(p[0], p[1], zLift));
    const top = footRing.map(p => P(p[0], p[1], zLift + st.zThick));

    v.sil.setAttribute("d", createPrism(foot, top));
    const fh = frontHalf(top);
    v.crease.setAttribute("d", line(fh));

    if (zLift > 1.5) {
      v.drop.setAttribute("d", seg(P(st.x, st.y, 0), P(st.x, st.y, zLift)));
      v.drop.style.opacity = Math.min(zLift / 8, 1);
    } else {
      v.drop.setAttribute("d", "");
    }

    if (idx === 0) {
      const slot = rrect(st.x - hw + 8, st.y - 4, st.x + hw - 8, st.y + 4, 2, 4);
      v.detail.setAttribute("d", poly(slot.map(p => P(p[0], p[1], zLift + st.zThick + 0.5))));
    } else if (idx === 1) {
      const chord1 = seg(P(st.x - hw * 0.7, st.y - 5, zLift + st.zThick + 0.5), P(st.x + hw * 0.7, st.y - 5, zLift + st.zThick + 0.5));
      const chord2 = seg(P(st.x - hw * 0.85, st.y, zLift + st.zThick + 0.5), P(st.x + hw * 0.85, st.y, zLift + st.zThick + 0.5));
      const chord3 = seg(P(st.x - hw * 0.7, st.y + 5, zLift + st.zThick + 0.5), P(st.x + hw * 0.7, st.y + 5, zLift + st.zThick + 0.5));
      v.detail.setAttribute("d", `${chord1} ${chord2} ${chord3}`);
    } else if (idx === 2) {
      if (v.pips) {
        const angles = [0, 45, 90, 135, 180, 225, 270, 315];
        angles.forEach((deg, i) => {
          const a = deg * (Math.PI / 180);
          const px = st.x + (hw - 6) * Math.cos(a);
          const py = st.y + (hh - 6) * Math.sin(a);
          const sp = P(px, py, zLift + st.zThick + 0.5);
          v.pips[i].setAttribute("cx", f(sp[0]));
          v.pips[i].setAttribute("cy", f(sp[1]));
        });
      }
    }
  }

  function renderStationPad(v, zLift) {
    const st = v.st;
    const hw = st.w / 2, hh = st.h / 2;
    const footRing = rrect(st.x - hw, st.y - hh, st.x + hw, st.y + hh, st.r, 5);
    const foot = footRing.map(p => P(p[0], p[1], zLift));
    const top = footRing.map(p => P(p[0], p[1], zLift + st.zThick));

    v.sil.setAttribute("d", createPrism(foot, top));
    v.crease.setAttribute("d", line(frontHalf(top)));

    if (zLift > 1.5) {
      v.drop.setAttribute("d", seg(P(st.x, st.y, 0), P(st.x, st.y, zLift)));
      v.drop.style.opacity = Math.min(zLift / 6, 1);
    } else {
      v.drop.setAttribute("d", "");
    }
  }

  let autoTimer = null;
  function playTrace(onStep = null, speed = 800) {
    isAutoPlay = true;
    let step = 1;
    selectStage(1, true);
    if (onStep) onStep(1);

    clearInterval(autoTimer);
    autoTimer = setInterval(() => {
      step++;
      if (step > 4) {
        clearInterval(autoTimer);
        isAutoPlay = false;
      } else {
        selectStage(step, true);
        if (onStep) onStep(step);
      }
    }, speed);
  }

  function runLiveTrace(isTp, onStep = null, onDone = null) {
    setVerdict(isTp);
    isAutoPlay = true;
    let step = 1;
    packetT = 0.05;
    selectStage(1, true);
    if (onStep) onStep(1);

    clearInterval(autoTimer);
    autoTimer = setInterval(() => {
      step++;
      if (step > 4) {
        clearInterval(autoTimer);
        isAutoPlay = false;
        if (onDone) onDone();
      } else {
        selectStage(step, true);
        if (onStep) onStep(step);
      }
    }, 450);
  }

  const observer = new IntersectionObserver(([entry]) => {
    if (entry.isIntersecting) {
      if (!isRunning) {
        isRunning = true;
        lastTime = performance.now();
        rafId = requestAnimationFrame(tick);
      }
    } else {
      isRunning = false;
      cancelAnimationFrame(rafId);
    }
  });
  observer.observe(hostElement);

  selectStage(1, false);
  rafId = requestAnimationFrame(tick);

  return {
    selectStage,
    setScenario,
    setVerdict,
    runLiveTrace,
    playTrace,
    destroy() {
      isRunning = false;
      cancelAnimationFrame(rafId);
      clearInterval(autoTimer);
      observer.disconnect();
      hostElement.innerHTML = "";
    }
  };
}

if (typeof window !== "undefined") {
  window.mountTriagePipeline = mountTriagePipeline;
}
if (typeof module !== "undefined" && module.exports) {
  module.exports = { mountTriagePipeline };
}
