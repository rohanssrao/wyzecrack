"use strict";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const mmss = (s) => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const macKey = (mac) => (mac || "").replace(/:/g, "").toUpperCase();
const isLocal = ["127.0.0.1", "localhost", "[::1]", "::1"].includes(location.hostname);

async function api(path, body) {
  const r = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  let j = {};
  try { j = await r.json(); } catch (e) { /* no body */ }
  if (!r.ok && !j.error) j.error = `HTTP ${r.status}`;
  return j;
}

// ---------------------------------------------------------------- icons
const ICONS = {
  "arrow-left": '<path d="M19 12H5M11 18l-6-6 6-6"/>',
  refresh: '<path d="M20 12a8 8 0 1 1-2.34-5.66"/><path d="M20 4v5h-5"/>',
  pencil: '<path d="M4 20h4L18.5 9.5a2.12 2.12 0 0 0-3-3L5 17v3z"/><path d="M13.5 8.5l2 2"/>',
  "sound-off": '<path d="M11 5 6 9H3v6h3l5 4V5z"/><path d="m16 9.5 5 5m0-5-5 5"/>',
  "sound-on": '<path d="M11 5 6 9H3v6h3l5 4V5z"/><path d="M15.5 8.5a5 5 0 0 1 0 7"/><path d="M18.5 5.5a9 9 0 0 1 0 13"/>',
  camera: '<path d="M4 8h3l1.5-2.5h7L17 8h3v11H4z"/><circle cx="12" cy="13.2" r="3.3"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  shrink: '<path d="M9 4v5H4M15 4v5h5M9 20v-5H4M15 20v-5h5"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  download: '<path d="M12 4v11M7 10.5l5 5 5-5M5 20h14"/>',
  trash: '<path d="M4 7h16M9.5 7V4.5h5V7M6.5 7l.9 12.5h9.2L17.5 7M10 11v5.5M14 11v5.5"/>',
  folder: '<path d="M3.5 7.5A1.5 1.5 0 0 1 5 6h4l2 2h8a1.5 1.5 0 0 1 1.5 1.5v8A1.5 1.5 0 0 1 19 19H5a1.5 1.5 0 0 1-1.5-1.5z"/>',
  video: '<rect x="3" y="6.5" width="12.5" height="11" rx="2"/><path d="m15.5 10.5 5-3v9l-5-3"/>',
};
const icon = (name) => `<svg class="i" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name]}</svg>`;
for (const e of document.querySelectorAll("[data-icon]")) e.insertAdjacentHTML("afterbegin", icon(e.dataset.icon));

// ---------------------------------------------------------------- state
let state = { phase: "idle" };   // the server's live view
let cams = new Map();            // MAC key -> camera, from the last scan
let current = null;              // the camera whose page is open
let view = {};                   // this page's live view: pending, ended, picture, saved, saveError
let captures = {};               // MAC key -> {on, error}
let connectSince = null, recStart = null, scanning = null, quitting = false;

const mine = () => current && state.camera && macKey(state.camera.mac) === macKey(current.mac);
const keyRead = () => mine() && state.phase === "starting" && state.steps?.enr && state.steps.enr.status !== "done";
const running = () => mine() && !["idle", "error"].includes(state.phase);
const displayName = (c) => c.name || c.model || "Wyze camera";

// ---------------------------------------------------------------- dialogs, toasts
function confirmDialog({ title, text = "", ok, cancel = "Cancel", danger = false }) {
  const d = $("#confirm");
  $("#confirm-title").textContent = title;
  $("#confirm-text").textContent = text;
  $("#confirm-ok").textContent = ok;
  $("#confirm-ok").className = "btn " + (danger ? "danger" : "primary");
  $("#confirm-cancel").textContent = cancel;
  d.returnValue = "cancel";
  d.showModal();
  $("#confirm-cancel").focus();
  return new Promise((resolve) => d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true }));
}

function toast(text, error) {
  const t = el("div", "toast" + (error ? " error" : ""), esc(text));
  $("#toasts").append(t);
  setTimeout(() => t.remove(), error ? 8000 : 4000);
}

// ---------------------------------------------------------------- routing
// #/ is the camera list, #/camera/<MAC> a camera's page
let shown;                        // the route on screen
const routeKey = () => (location.hash.match(/^#\/camera\/([0-9A-F]{12})$/) || [])[1] || null;

async function onRoute() {
  const key = routeKey();
  if (key === shown) return;
  if (shown && current) {
    if (keyRead() && !(await confirmDialog({ title: "Stop reading the key?", text: "Starting over takes another 1–4 minutes.", ok: "Stop", cancel: "Keep waiting" }))) {
      location.hash = `#/camera/${shown}`;   // stay (this hashchange is a no-op)
      return;
    }
    if (running()) api("/api/stop", {});
    closeCamera();
  }
  shown = key;
  if (key) openCamera(key); else showHome();
}
window.addEventListener("hashchange", onRoute);

// ---------------------------------------------------------------- cameras
function showHome() {
  document.title = "wyzecrack";
  $("#camera").classList.add("hidden");
  $("#home").classList.remove("hidden");
  renderCams();
  scan();
}

function scan() {
  if (scanning) return scanning;
  const b = $("#rescan");
  b.disabled = true;
  b.querySelector("span").textContent = "Scanning…";
  if (!cams.size) renderSkeleton();
  scanning = (async () => {
    let list = null;
    try { list = await api("/api/cameras"); } catch (e) { /* offline */ }
    if (Array.isArray(list)) cams = new Map(list.map((c) => [macKey(c.mac), c]));
    scanning = null;
    b.disabled = false;
    b.querySelector("span").textContent = "Rescan";
    if (!shown) renderCams(true);
  })();
  return scanning;
}

function renderSkeleton() {
  const box = $("#cams");
  box.innerHTML = "";
  for (let i = 0; i < 3; i++) box.append(el("div", "card skeleton", `<div class="thumb"></div><div class="card-body"><div></div><div></div></div>`));
}

function renderCams(scanned) {
  const box = $("#cams");
  if (!cams.size) {
    if (scanned) box.innerHTML = "";
    $("#nocams").classList.toggle("hidden", !scanned);
    return;
  }
  $("#nocams").classList.add("hidden");
  box.innerHTML = "";
  for (const c of cams.values()) box.append(card(c));
}

function cameraStatus(c) {
  const cap = captures[macKey(c.mac)];
  if (c.online === false) return ["Not answering", true];
  if (cap?.error || c.capturing === "error") return ["Motion clips stopped", true];
  if (!c.key_known) return ["New", false];
  if (cap?.on || c.capturing === "on") return ["Saving motion clips", false];
  if (!c.tested) return ["Untested model", false];
  return null;
}

function card(c) {
  const a = el("a", "card" + (c.online === false ? " off" : ""));
  a.href = `#/camera/${macKey(c.mac)}`;
  const st = cameraStatus(c);
  a.innerHTML = `<div class="thumb">${c.thumb ? `<img src="${esc(c.thumb)}" alt="" loading="lazy">` : icon("video")}</div>
    <div class="card-body"><div class="card-name">${esc(displayName(c))}</div>
    <div class="card-meta">${esc(c.model)} · ${esc(c.ip)}</div>
    ${st ? `<div class="card-status${st[1] ? " warn" : ""}">${esc(st[0])}</div>` : ""}</div>`;
  return a;
}

$("#rescan").onclick = () => scan();

// ---------------------------------------------------------------- a camera's page
async function openCamera(key) {
  let cam = cams.get(key) || (state.camera && macKey(state.camera.mac) === key ? state.camera : null);
  if (!cam) { await scan(); cam = cams.get(key); }
  if (routeKey() !== key) return;
  if (!cam) { location.hash = "#/"; return; }
  current = cam;
  document.title = `${displayName(cam)} · wyzecrack`;
  $("#home").classList.add("hidden");
  $("#camera").classList.remove("hidden");
  showTitle();
  $("#cam-meta").textContent = `${cam.model} · ${cam.ip}`;
  showMotion();
  clearLibrary();
  loadLibrary();
  if (running()) { view = { picture: state.phase === "live" }; render(); return; }  // already on
  startView();
}

function closeCamera() {
  current = null;
  view = {};
  resetVideo();
  closePlayer();
}

function showTitle() {
  $("#cam-name").textContent = displayName(current);
}

async function startView() {
  view = { pending: true };
  resetVideo();
  render();
  const cam = current;
  for (let i = 0; i < 40 && cam === current; i++) {
    const r = await api("/api/start", cam);
    if (!r.error) return;
    if (r.error !== "already running") { view = { ended: true, error: r.error }; render(); return; }
    await sleep(500);                // the previous view is still stopping
  }
}

$("#rename").onclick = () => {
  const box = $(".cam-title");
  const input = el("input");
  input.value = current.name || "";
  input.placeholder = current.model;
  input.setAttribute("aria-label", "Camera name");
  $("#cam-name").classList.add("hidden");
  $("#rename").classList.add("hidden");
  box.prepend(input);
  input.focus();
  input.select();
  let done = false;
  const finish = async (save) => {
    if (done) return;
    done = true;
    input.remove();
    $("#cam-name").classList.remove("hidden");
    $("#rename").classList.remove("hidden");
    if (!save) return;
    const name = input.value.trim();
    const r = await api("/api/name", { mac: current.mac, ip: current.ip, name });
    if (r.error) { toast("Couldn't rename the camera", true); return; }
    current.name = name || null;
    showTitle();
    document.title = `${displayName(current)} · wyzecrack`;
  };
  input.onkeydown = (e) => { if (e.key === "Enter") finish(true); if (e.key === "Escape") finish(false); };
  input.onblur = () => finish(true);
};

// what the video area shows, from the server's state and this page's view
function kind() {
  if (view.error) return "start_failed";
  if (!mine() || state.phase === "idle") {
    if (view.pending) return "starting";
    if (view.saveError) return "save_failed";
    if (view.picture) return view.saved ? "saved" : "saving";
    return "stopped";
  }
  const p = state.phase, st = state.steps || {};
  if (p === "error") return state.error_kind === "no_answer" ? "no_answer" : "error";
  if (p === "live" || p === "stopping" || p === "connecting") return p;
  if (st.enr?.status === "problem") return "refused";
  if (st.enr?.status === "active") return st.enr.detail?.nudging ? "key" : "key_wait";
  if (st.uid?.status === "active") return "uid";
  return "starting";
}

const VIEWS = {
  starting: { spin: true, title: "Starting" },
  live: { title: "" },
  key: { spin: true, title: "Reading the camera's key", text: "First time only. Usually takes 1–4 minutes." },
  key_wait: { spin: true, title: "Waiting for the camera's key", text: "First time only. Usually within 20 minutes." },
  refused: { title: "Can't read this camera's key", text: "Its firmware no longer trusts the eMudhra certificate." },
  uid: { spin: true, title: "Getting the camera's ID" },
  connecting: { spin: true, title: "Connecting" },
  stopping: { spin: true, title: "Stopping" },
  saving: { spin: true, title: "Saving" },
  saved: { title: "Saved" },
  stopped: { title: "Stopped" },
  save_failed: { title: "Couldn't save the recording" },
  no_answer: { title: "Camera not answering", text: "Check that it's switched on in the Wyze app." },
  error: { title: "Something went wrong" },
  start_failed: { title: "Couldn't start" },
};

function render() {
  if (!current) return;
  const k = kind(), v = VIEWS[k];
  const screen = $("#screen");
  screen.classList.toggle("live", k === "live");
  screen.classList.toggle("dim", ["saving", "saved", "save_failed", "stopping"].includes(k) && view.picture);
  $("#spinner").classList.toggle("hidden", !v.spin);
  $("#ov-title").textContent = v.title;
  $("#ov-text").textContent = k === "error" ? (state.error || "") : k === "save_failed" ? view.saveError
    : k === "start_failed" ? view.error : (v.text || "");
  let extra = "";
  if (k === "key" || k === "key_wait") {
    view.keySince = view.keySince || Date.now();
    extra = `${mmss((Date.now() - view.keySince) / 1000)} elapsed`;
  }
  if (k === "connecting") {
    connectSince = connectSince || Date.now();
    if (Date.now() - connectSince > 5000) extra = "This can take up to 30 seconds.";
  } else connectSince = null;
  $("#ov-extra").textContent = extra;

  // the bar under the picture: the stream's controls, or what to do next
  const live = k === "live";
  $("#stream").classList.toggle("hidden", !live);
  $("#live-tools").classList.toggle("hidden", !live);
  const actions = $("#actions");
  actions.innerHTML = "";
  const action = (label, cls, fn, title) => { const b = el("button", "btn " + cls, esc(label)); b.type = "button"; if (title) b.title = title; b.onclick = fn; actions.append(b); };
  if (live) action("Stop", "", stop);
  if (["starting", "key", "key_wait", "refused", "uid", "connecting"].includes(k)) action("Cancel", "", stop);
  if (k === "saved") action("Play recording", "", () => openPlayer(view.saved));
  if (["saved", "stopped", "save_failed", "start_failed"].includes(k)) action("Watch live", "primary", startView);
  if (k === "no_answer") action("Get its key again", "", rekey, "If the camera was set up again in the Wyze app");
  if (k === "error" || k === "no_answer") action("Try again", "primary", startView);
  if (live) updateTimer();
}

function stop() {
  if (view.pending && !mine()) { view = {}; render(); return; }
  api("/api/stop", {});
}

async function rekey() {
  if (!(await confirmDialog({
    title: "Read the camera's key again?",
    text: "Use this if the camera was set up again in the Wyze app. It usually takes 1–4 minutes.",
    ok: "Read key again",
  }))) return;
  await api("/api/rekey", { mac: current.mac });
  current.key_known = false;
  startView();
}

function updateTimer() {
  if (recStart) $("#rec-text").textContent = `Recording ${mmss(Date.now() / 1000 - recStart)}`;
}
setInterval(() => {
  if (!current) return;
  const k = kind();
  if (k === "live") updateTimer();
  if (k === "connecting" || k === "key" || k === "key_wait") render();
}, 1000);

function applyState(s) {
  const was = state;
  state = s;
  if (!current || !mine()) { if (current) render(); return; }
  if (s.phase !== "idle") view.pending = false;
  if (s.phase === "live") {
    if (!view.picture || was.phase !== "live") recStart = s.since || Date.now() / 1000;
    view.picture = true;
  }
  render();
}

// ---------------------------------------------------------------- motion clips
function showMotion() {
  const cap = captures[macKey(current.mac)];
  const t = $("#motion");
  t.checked = !!(cap ? cap.on || cap.error : current.motion);
  const err = $("#motion-error");
  err.textContent = cap?.error ? `Not saving motion clips: ${cap.error}` : "";
  err.classList.toggle("hidden", !cap?.error);
}

$("#motion").onchange = async (e) => {
  const t = e.target, on = t.checked, cam = current;
  if (on) {
    t.checked = false;              // until it's confirmed and on
    if (!(await confirmDialog({
      title: "Save this camera's motion clips?",
      text: "While wyzecrack runs, the camera's internet traffic goes through the computer running wyzecrack. If that computer sleeps or shuts down, the camera may be offline for up to a minute.",
      ok: "Turn on",
    }))) return;
  }
  t.disabled = true;
  let r;
  try { r = await api("/api/motion", { ...cam, on }); } catch (err) { r = { error: String(err) }; }
  finally { t.disabled = false; }
  if (cam !== current) return;
  if (r.error) { toast("Couldn't change motion clips", true); showMotion(); return; }
  cam.motion = on;
  if (on && r.capturing === "on") toast("Saving motion clips");
  showMotion();
};

// ---------------------------------------------------------------- saved
const fmtWhen = (t) => new Date(t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
let items = [];

function clearLibrary() {
  items = [];
  $("#saved-count").textContent = "";
  $("#folder-path").textContent = "";
  $("#saved").innerHTML = "";
}

async function loadLibrary() {
  if (!current) return;
  const cam = current;
  const lib = await api(`/api/library?mac=${encodeURIComponent(cam.mac)}&model=${encodeURIComponent(cam.model || "")}`);
  if (cam !== current || lib.error) return;
  items = [
    ...lib.recordings.map((r) => ({ t: r.started, url: r.video, img: r.thumb, kind: "Recording", len: r.seconds })),
    ...lib.motion.map((m) => ({ t: m.t, url: m.clip, img: m.snapshot, kind: "Motion clip", len: m.seconds })),
  ].sort((a, b) => b.t - a.t);
  $("#saved-count").textContent = items.length || "";
  $("#folder-path").textContent = lib.folder || "";
  $("#folder-path").title = lib.folder || "";
  $("#open-folder").classList.toggle("hidden", !isLocal);
  const box = $("#saved");
  box.innerHTML = "";
  if (!items.length) { box.append(el("p", "", "No recordings or motion clips yet.")); return; }
  for (const it of items) {
    const t = el("button", "tile");
    t.type = "button";
    t.innerHTML = `<div class="thumb">${it.img ? `<img src="${esc(it.img)}" alt="" loading="lazy">` : icon("video")}${it.len ? `<span class="len">${mmss(it.len)}</span>` : ""}</div>
      <div><div class="tile-when">${esc(fmtWhen(it.t))}</div><div class="tile-kind">${esc(it.kind)}</div></div>`;
    t.setAttribute("aria-label", `Play ${it.kind.toLowerCase()} from ${fmtWhen(it.t)}`);
    t.onclick = () => openPlayer(it.url);
    box.append(t);
  }
}

$("#open-folder").onclick = async () => {
  const r = await api("/api/open", { mac: current.mac, model: current.model });
  if (r.error) toast("Couldn't open the folder", true);
};

let playing = null;
function openPlayer(url) {
  const it = items.find((x) => x.url === url);
  if (!it) return;
  playing = it;
  $("#play-error").classList.add("hidden");
  $("#play-title").textContent = `${it.kind} · ${fmtWhen(it.t)}`;
  const v = $("#play-video");
  v.src = it.url;
  const dl = $("#play-download");
  dl.href = it.url;
  dl.download = `${displayName(current).replace(/\W+/g, "-")}-${new Date(it.t * 1000).toISOString().slice(0, 16).replace(/[:T]/g, "")}.mp4`;
  $("#play-dialog").showModal();
  v.play().catch(() => {});
}

function closePlayer() {
  const d = $("#play-dialog");
  if (d.open) d.close();
}

$("#play-close").onclick = closePlayer;
$("#play-dialog").addEventListener("close", () => { const v = $("#play-video"); v.pause(); v.removeAttribute("src"); v.load(); playing = null; });
$("#play-dialog").addEventListener("click", (e) => { if (e.target.id === "play-dialog") closePlayer(); });
$("#play-delete").onclick = async () => {
  const it = playing;
  if (!it) return;
  $("#play-video").pause();
  const what = it.kind === "Recording" ? "recording" : "motion clip";
  if (!(await confirmDialog({ title: `Delete this ${what}?`, text: `${displayName(current)} · ${fmtWhen(it.t)}`, ok: "Delete", danger: true }))) return;
  const r = await api("/api/delete", { url: it.url });
  if (r.error) {
    const e = $("#play-error");
    e.textContent = `Couldn't delete the ${what}.`;
    e.classList.remove("hidden");
    return;
  }
  closePlayer();
  toast(it.kind === "Recording" ? "Recording deleted" : "Motion clip deleted");
  if (view.saved === it.url) { view.picture = false; view.saved = null; render(); }
  loadLibrary();
};

// ---------------------------------------------------------------- quit
$("#quit").onclick = async () => {
  if (!(await confirmDialog({ title: "Quit wyzecrack?", text: "Any live view is saved first. Motion clips stop.", ok: "Quit" }))) return;
  quitting = true;
  await api("/api/quit", {});
  document.querySelector("main").innerHTML = `<div class="stopped"><h1>wyzecrack has stopped</h1><p>You can close this tab.</p></div>`;
  $("#quit").remove();
};

// ---------------------------------------------------------------- live video
const canvas = $("#video");
const ctx2d = canvas.getContext("2d");
let decoder = null, waitKey = true;
// "h264": the browser decodes the stream (WebCodecs); "jpeg": it can't, so
// the server sends still frames instead
let videoMode = "h264", framesShown = 0, sock = null;

function wantJpeg() {
  if (videoMode === "jpeg") return;
  videoMode = "jpeg";
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = null;
  if (sock && sock.readyState === 1) sock.send(JSON.stringify({ kind: "want", video: "jpeg" }));
}

// the picture's size: the canvas follows it, and the bar shows it
function fit(w, h) {
  if (canvas.width === w && canvas.height === h) return;
  canvas.width = w;
  canvas.height = h;
  const res = $("#res");
  res.textContent = videoMode === "jpeg" ? "Still frames" : `${h}p`;
  res.title = videoMode === "jpeg" ? "This browser can't play the video stream. The recording is full quality." : "";
}

function onJpeg(buf) {
  const blob = new Blob([new Uint8Array(buf, 9)], { type: "image/jpeg" });
  createImageBitmap(blob).then((bmp) => {
    fit(bmp.width, bmp.height);
    ctx2d.drawImage(bmp, 0, 0);
    bmp.close();
    framesShown++;
  }).catch(() => {});
}

function resetVideo() {
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = null;
  waitKey = true;
  recStart = null;
  ctx2d.clearRect(0, 0, canvas.width, canvas.height);
  $("#screen").classList.remove("live", "dim");
}

async function configure(cfg) {
  if (videoMode === "jpeg") return;
  let ok = "VideoDecoder" in window;
  if (ok) {
    try { ok = (await VideoDecoder.isConfigSupported({ codec: cfg.codec })).supported; } catch (e) { ok = false; }
  }
  if (!ok) { wantJpeg(); return; }
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = new VideoDecoder({
    output: (frame) => {
      fit(frame.displayWidth, frame.displayHeight);
      ctx2d.drawImage(frame, 0, 0);
      frame.close();
      framesShown++;
    },
    // a decoder that never managed a picture won't: use still frames
    error: () => { if (!framesShown) wantJpeg(); else waitKey = true; },
  });
  decoder.configure({ codec: cfg.codec, optimizeForLatency: true });
  waitKey = true;
}

function onVideo(buf) {
  if (!decoder || decoder.state !== "configured") return;
  const dv = new DataView(buf);
  const key = dv.getUint8(1) === 1;
  if (waitKey && !key) return;
  if (decoder.decodeQueueSize > 30 && !key) { waitKey = true; return; }
  waitKey = false;
  try {
    decoder.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp: Math.round(dv.getFloat64(2) * 1e6), data: new Uint8Array(buf, 10) }));
  } catch (e) { waitKey = true; }
}

// audio: s16le PCM, 8 kHz mono
let actx = null, audioOn = false, nextT = 0;
function showAudio() {
  const b = $("#audio");
  b.innerHTML = icon(audioOn ? "sound-on" : "sound-off");
  b.setAttribute("aria-label", audioOn ? "Turn sound off" : "Turn sound on");
  b.title = audioOn ? "Sound on" : "Sound off";
}
$("#audio").onclick = () => {
  audioOn = !audioOn;
  if (audioOn && !actx) actx = new AudioContext();
  if (actx) (audioOn ? actx.resume() : actx.suspend());
  nextT = 0;
  showAudio();
};
showAudio();

function onAudio(buf) {
  if (!audioOn || !actx) return;
  const pcm = new Int16Array(buf.slice(9));
  const b = actx.createBuffer(1, pcm.length, 8000);
  const ch = b.getChannelData(0);
  for (let i = 0; i < pcm.length; i++) ch[i] = pcm[i] / 32768;
  const src = actx.createBufferSource();
  src.buffer = b;
  src.connect(actx.destination);
  const now = actx.currentTime;
  if (nextT < now + 0.03 || nextT > now + 1) nextT = now + 0.15;
  src.start(nextT);
  nextT += b.duration;
}

$("#shot").onclick = () => {
  canvas.toBlob((blob) => {
    const a = el("a");
    a.href = URL.createObjectURL(blob);
    a.download = `${displayName(current).replace(/\W+/g, "-")}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "")}.png`;
    a.click();
    toast("Still saved");
  });
};

function showFull() {
  const full = !!document.fullscreenElement;
  const b = $("#full");
  b.innerHTML = icon(full ? "shrink" : "expand");
  b.setAttribute("aria-label", full ? "Exit full screen" : "Full screen");
  b.title = full ? "Exit full screen" : "Full screen";
}
$("#full").onclick = () => { document.fullscreenElement ? document.exitFullscreen() : $("#player").requestFullscreen(); };
document.addEventListener("fullscreenchange", showFull);
showFull();

// ---------------------------------------------------------------- socket
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  sock = ws;
  ws.binaryType = "arraybuffer";
  ws.onopen = () => {
    $("#offline").classList.add("hidden");
    if (videoMode === "jpeg") ws.send(JSON.stringify({ kind: "want", video: "jpeg" }));
  };
  ws.onmessage = (m) => {
    if (typeof m.data !== "string") {
      const k = new DataView(m.data).getUint8(0);
      if (k === 1) onVideo(m.data); else if (k === 2) onAudio(m.data); else if (k === 3) onJpeg(m.data);
      return;
    }
    const ev = JSON.parse(m.data);
    switch (ev.kind) {
      case "state": applyState(ev); break;
      case "video_config": configure(ev); break;
      case "library":
        if (ev.new && current && mine()) { view.saved = ev.new; render(); }
        else if (ev.new) toast("Recording saved");
        loadLibrary();
        break;
      case "save_failed":
        if (current && mine()) { view.saveError = ev.error; render(); } else toast("Couldn't save the recording", true);
        break;
      case "motion":
        toast("Motion clip saved");
        loadLibrary();
        break;
      case "toast": toast(ev.text, ev.level === "error"); break;
      case "captures":
        captures = ev.captures || {};
        if (current) showMotion(); else if (cams.size) renderCams(true);
        break;
    }
  };
  ws.onclose = () => {
    if (quitting) return;
    $("#offline").classList.remove("hidden");
    setTimeout(connect, 1500);
  };
}

connect();
shown = routeKey();
if (shown) openCamera(shown); else showHome();
