"use strict";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const mmss = (s) => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const api = (path, body) => fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}).then((r) => r.json());

let state = { phase: "idle" };
let camera = null;
let hadPicture = false;     // this live view showed a picture (so it is saved)
let ended = false;          // the page shows the ended view (Saving / Saved)
let savedNew = false;       // this view's recording has been written

// ---------------------------------------------------------------- picker
async function scan() {
  $("#scan").classList.remove("hidden");
  $("#cams").innerHTML = "";
  $("#nocams").classList.add("hidden");
  let cams = [];
  try { cams = await api("/api/cameras"); } catch (e) { cams = []; }
  $("#scan").classList.add("hidden");
  if (!cams.length) { $("#nocams").classList.remove("hidden"); return; }
  for (const c of cams) $("#cams").append(camCard(c));
}

function displayName(c) { return c.name || c.model || "Wyze camera"; }

function camCard(c) {
  const card = el("div", "cam" + (c.online === false ? " off" : ""));
  const thumb = el("div", "thumb", (c.thumb ? `<img src="${esc(c.thumb)}" alt="">` : `<span class="ph">📷</span>`) + `<div class="go">Watch</div>`);
  const body = el("div", "body");
  const name = el("div", "name", `<span>${esc(displayName(c))}</span><button class="edit" title="Rename">✎</button>`);
  const status = c.online === false ? "not answering" : c.ready ? "ready" : c.key_known ? "key saved" : null;
  const saving = c.capturing === "on" ? "saving motion clips" : c.capturing === "error" ? "motion clips: not saving" : null;
  const bits = [c.name ? c.model : null, c.ip, status, saving, c.tested ? null : "untested model"].filter(Boolean);
  const meta = el("div", "meta", esc(bits.join(" · ")));
  name.querySelector(".edit").onclick = (ev) => { ev.stopPropagation(); rename(c, name); };
  card.onclick = () => start(c);
  body.append(name, meta);
  card.append(thumb, body);
  return card;
}

function rename(c, node) {
  const input = el("input");
  input.value = c.name || "";
  input.placeholder = c.model;
  node.innerHTML = "";
  node.append(input);
  input.focus();
  input.onclick = (e) => e.stopPropagation();
  const done = async () => {
    c.name = input.value.trim() || null;
    await api("/api/name", { mac: c.mac, ip: c.ip, name: input.value });
    node.innerHTML = `<span>${esc(displayName(c))}</span><button class="edit" title="Rename">✎</button>`;
    node.querySelector(".edit").onclick = (ev) => { ev.stopPropagation(); rename(c, node); };
  };
  input.onkeydown = (e) => { if (e.key === "Enter") input.blur(); if (e.key === "Escape") { input.value = c.name || ""; input.blur(); } };
  input.onblur = done;
}

async function start(c) {
  camera = c;
  hadPicture = ended = savedNew = false;
  $("#again").classList.add("hidden");
  const r = await api("/api/start", { ...c, name: c.name });
  if (r.error) toast(r.error, "error");
  showSession(c);
}

// ---------------------------------------------------------------- session
function showSession(c) {
  camera = c;
  $("#picker").classList.add("hidden");
  $("#session").classList.remove("hidden");
  $("#cam-name").textContent = displayName(c);
  $("#cam-sub").textContent = c.name ? `${c.model} · ${c.ip}` : c.ip;
  showMotion(c);
  loadLibrary();
}

function showPicker() {
  ended = false;
  $("#again").classList.add("hidden");
  $("#session").classList.add("hidden");
  $("#picker").classList.remove("hidden");
  resetVideo();
  scan();
}

const STATUS = {
  starting: ["⌁", "spin", "Starting", "Checking the network and the camera."],
  key: ["🔑", "pulse", "Waiting for the camera's key", "It's read from the camera's own reports to Wyze, which it sends every 20 minutes or so, and right away when it sees motion. This happens once per camera."],
  key_nudge: ["🔑", "pulse", "Getting the camera's key", "Its connection to Wyze is reset a few times, which makes it report in with its key. About a minute, once per camera."],
  uid: ["🪪", "spin", "Asking Wyze for the camera's ID", "With the camera's own key, the way the camera itself asks."],
  direct: ["⚡", "spin", "Connecting to the camera", "Straight over your network; nothing is rerouted."],
  enr_refused: ["🔒", "bad", "The camera refused our certificate", "This firmware no longer trusts the eMudhra CA, so its key can't be read this way."],
  stopping: ["⏻", "spin", "Stopping", "Putting the camera's network back the way it was."],
  stopping_direct: ["⏻", "spin", "Stopping", "Saving the recording."],
  stopping_plain: ["⏻", "spin", "Stopping", ""],
  error: ["!", "bad", "Something went wrong", ""],
  no_answer: ["!", "bad", "The camera doesn't answer", ""],
  ended_saving: ["💾", "spin", "Saving", "Writing the recording…"],
  ended: ["✓", "ok", "Saved", "This live view is at the top of Saved, below."],
};

function setStatus(key, extra) {
  const [icon, anim, title, text] = STATUS[key] || STATUS.starting;
  const i = $("#status-icon");
  i.textContent = icon;
  i.className = "status-icon " + anim;
  $("#status-title").textContent = title;
  $("#status-text").textContent = key === "error" || key === "no_answer" ? (state.error || "") : text;
  $("#status-extra").textContent = extra || "";
}

const STEPS = [["enr", "Key"], ["uid", "Camera ID"], ["live", "Live"]];
$("#steps").innerHTML = STEPS.map(([k, label]) => `<li data-step="${k}">${label}</li>`).join("");

function applyState(s) {
  const prev = state.phase;
  state = s;
  if (s.phase === "idle") {
    if (!$("#session").classList.contains("hidden") && prev !== "idle") {
      if (hadPicture) showEnded(); else showPicker();
    }
    return;
  }
  if (s.camera && $("#session").classList.contains("hidden")) showSession(s.camera);
  const steps = s.steps || {};
  for (const li of document.querySelectorAll("#steps li")) {
    const st = steps[li.dataset.step];
    li.className = st ? st.status : "";
  }
  const last = document.querySelector('#steps li[data-step="live"]');
  if (s.phase === "live") last.className = "done";
  else if (s.phase === "connecting") last.className = "active";

  // first time with a camera: the key, then the ID; then connecting
  const keyRead = steps.enr?.status === "active" || steps.uid?.status === "active";
  let key = s.phase;
  if (s.phase === "starting") key = steps.enr?.status !== "done" ? "key" : steps.uid?.status !== "done" ? "uid" : "direct";
  if (steps.enr?.status === "active" && s.phase !== "error") key = steps.enr.detail?.nudging ? "key_nudge" : "key";
  if (steps.enr?.status === "problem") key = "enr_refused";
  if (steps.uid?.status === "active") key = "uid";
  if (s.phase === "connecting") key = "direct";
  if (s.phase === "stopping") key = keyRead ? "stopping" : hadPicture ? "stopping_direct" : "stopping_plain";
  if (s.phase === "error" && s.error_kind === "no_answer") key = "no_answer";
  let extra = "";
  if (key === "key") { const n = steps.enr?.detail?.seen || 0; extra = n ? `${n} camera connection${n > 1 ? "s" : ""} read so far` : ""; }
  if (key === "key_nudge") { const r = steps.enr?.detail?.resets || 0; extra = r ? `Reset ${r} of up to 8` : ""; }
  if (key === "direct") {
    if (prev !== "connecting" || !connectSince) connectSince = Date.now();
    const secs = Math.round((Date.now() - connectSince) / 1000);
    if (secs >= 5) extra = `Still waiting for the camera to answer (${secs} s).`;
  } else connectSince = null;
  $("#rekey").classList.toggle("hidden", !(s.phase === "error" && s.error_kind === "no_answer"));
  const stage = $("#stage");
  stage.classList.toggle("is-live", s.phase === "live");
  $("#hud").classList.toggle("hidden", s.phase !== "live");
  if (s.phase !== "live") setStatus(key, extra);
  if (s.phase === "live" && prev !== "live") { recStart = (s.since || Date.now() / 1000); $("#stage").classList.remove("dim"); hadPicture = true; }
  $("#stop").textContent = s.phase === "error" ? "Back" : "Stop";
}

$("#stop").onclick = async () => {
  if (state.phase === "error" || state.phase === "idle") { showPicker(); return; }
  await api("/api/stop", {});
};
$("#quit").onclick = async () => {
  if (!confirm("Quit wyzecrack? Anything it changed on the network is put back.")) return;
  await api("/api/quit", {});
  document.body.innerHTML = `<main><div class="hero"><h1>wyzecrack stopped</h1><p>The network is back to normal. You can close this tab.</p></div></main>`;
};
$("#rescan").onclick = scan;

// the view ended and was saved: stay on the camera's page, its recording
// at the top of Saved
function showEnded() {
  ended = true;
  resetVideo(true);
  $("#stage").classList.add("dim");
  $("#hud").classList.add("hidden");
  $("#rekey").classList.add("hidden");
  setStatus(savedNew ? "ended" : "ended_saving");
  $("#again").classList.remove("hidden");
  $("#stop").textContent = "Back";
}
$("#again").onclick = () => { if (camera) start(camera); };

$("#rekey").onclick = async () => {
  if (!camera) return;
  $("#rekey").classList.add("hidden");
  await api("/api/rekey", { mac: camera.mac });
  await start(camera);
};

// ---------------------------------------------------------------- motion clips
let captures = {};
const macKey = (mac) => (mac || "").replace(/:/g, "").toUpperCase();

function showMotion(c) {
  const cap = captures[macKey(c.mac)];
  $("#motion-toggle").checked = !!(cap ? cap.on || cap.error : c.motion);
  const note = $("#motion-note");
  note.classList.toggle("error", !!(cap && cap.error));
  note.textContent = cap && cap.error
    ? `Not saving motion clips: ${cap.error}`
    : "While wyzecrack is open, this camera's internet traffic goes through this computer so its clips can be copied. If this computer sleeps or shuts down meanwhile, the camera is offline for up to about a minute.";
}

$("#motion-toggle").onchange = async (e) => {
  if (!camera) return;
  const on = e.target.checked;
  camera.motion = on;
  const r = await api("/api/motion", { ...camera, on });
  if (on && r.capturing === "on") toast("Saving this camera's motion clips");
  else if (!on) toast("No longer saving motion clips");
};

// ---------------------------------------------------------------- library
async function loadLibrary(fresh) {
  if (!camera) return;
  const lib = await api(`/api/library?mac=${encodeURIComponent(camera.mac)}`);
  const items = [
    ...lib.recordings.map((r) => ({ t: r.started, src: r.video, img: r.thumb, kind: "live", len: mmss(r.seconds) })),
    ...lib.motion.map((m) => ({ t: m.t, src: m.clip, img: m.snapshot, kind: "motion", len: m.seconds ? mmss(m.seconds) : "" })),
  ].sort((a, b) => b.t - a.t);
  const box = $("#saved");
  $("#saved-count").textContent = items.length || "";
  if (!items.length) { box.innerHTML = `<p class="muted">Live views you watch are saved here.</p>`; return; }
  box.innerHTML = "";
  for (const it of items) {
    const t = el("div", "tile" + (fresh && it.src === fresh ? " fresh" : ""));
    const when = new Date(it.t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    t.innerHTML = `<div class="img" style="background-image:url('${esc(it.img || "")}')"><span class="pill kind">${it.kind === "live" ? "Live view" : "Motion"}</span>${it.len ? `<span class="pill len">${it.len}</span>` : ""}<div class="play">▶</div></div><div class="cap">${when}</div>`;
    if (it.src) t.onclick = () => play(it.src);
    box.append(t);
  }
}

function play(src) {
  const p = $("#player");
  p.src = src;
  $("#modal").classList.remove("hidden");
  p.play().catch(() => {});
}
$("#modal-close").onclick = () => { $("#player").pause(); $("#modal").classList.add("hidden"); };
$("#modal").onclick = (e) => { if (e.target.id === "modal") $("#modal-close").onclick(); };

function toast(text, level) {
  const t = el("div", "toast" + (level === "error" ? " error" : ""), esc(text));
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 6000);
}

// ---------------------------------------------------------------- live video
const canvas = $("#video");
const ctx2d = canvas.getContext("2d");
let decoder = null, waitKey = true, recStart = null, connectSince = null;
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

function onJpeg(buf) {
  const blob = new Blob([new Uint8Array(buf, 9)], { type: "image/jpeg" });
  createImageBitmap(blob).then((bmp) => {
    if (canvas.width !== bmp.width) { canvas.width = bmp.width; canvas.height = bmp.height; }
    ctx2d.drawImage(bmp, 0, 0);
    bmp.close();
    framesShown++;
  }).catch(() => {});
}

function resetVideo(keepLastFrame) {
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = null; waitKey = true;
  $("#stage").classList.remove("is-live");
  if (!keepLastFrame) { $("#stage").classList.remove("dim"); ctx2d.clearRect(0, 0, canvas.width, canvas.height); }
}

async function configure(cfg) {
  if (cfg.width) $("#res").textContent = `${cfg.height}p`;
  if (videoMode === "jpeg") return;
  let ok = "VideoDecoder" in window;
  if (ok) {
    try { ok = (await VideoDecoder.isConfigSupported({ codec: cfg.codec })).supported; } catch (e) { ok = false; }
  }
  if (!ok) { wantJpeg(); return; }
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = new VideoDecoder({
    output: (frame) => {
      if (canvas.width !== frame.displayWidth) { canvas.width = frame.displayWidth; canvas.height = frame.displayHeight; }
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
  const ts = dv.getFloat64(2);
  try {
    decoder.decode(new EncodedVideoChunk({ type: key ? "key" : "delta", timestamp: Math.round(ts * 1e6), data: new Uint8Array(buf, 10) }));
  } catch (e) { waitKey = true; }
}

// audio: s16le PCM, 8 kHz mono
let actx = null, audioOn = false, nextT = 0;
$("#audio").onclick = () => {
  audioOn = !audioOn;
  if (audioOn && !actx) actx = new AudioContext();
  if (actx) (audioOn ? actx.resume() : actx.suspend());
  $("#audio").textContent = audioOn ? "🔊" : "🔇";
  nextT = 0;
};
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
    a.download = `${(camera ? displayName(camera) : "wyze").replace(/\W+/g, "-")}-${new Date().toISOString().slice(0, 19).replace(/:/g, "")}.png`;
    a.click();
    toast("Still saved to your downloads");
  });
};
$("#full").onclick = () => { const s = $("#stage"); document.fullscreenElement ? document.exitFullscreen() : s.requestFullscreen(); };

setInterval(() => {
  if (state.phase === "live" && recStart) $("#rec").textContent = mmss(Date.now() / 1000 - recStart);
  if (state.phase === "connecting" && connectSince) applyState(state);
}, 1000);

// ---------------------------------------------------------------- socket
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  sock = ws;
  ws.binaryType = "arraybuffer";
  ws.onopen = () => { if (videoMode === "jpeg") ws.send(JSON.stringify({ kind: "want", video: "jpeg" })); };
  ws.onmessage = (m) => {
    if (typeof m.data !== "string") {
      const kind = new DataView(m.data).getUint8(0);
      if (kind === 1) onVideo(m.data); else if (kind === 2) onAudio(m.data); else if (kind === 3) onJpeg(m.data);
      return;
    }
    const ev = JSON.parse(m.data);
    switch (ev.kind) {
      case "state": applyState(ev); break;
      case "video_config": configure(ev); break;
      case "library":
        loadLibrary(ev.new);
        if (ev.new) {
          savedNew = true;
          if (ended) setStatus("ended");
          else if ($("#session").classList.contains("hidden")) toast("Live view saved");
        }
        break;
      case "motion":
        toast("Motion detected · clip saved");
        loadLibrary();
        break;
      case "toast": toast(ev.text, ev.level); break;
      case "captures": captures = ev.captures || {}; if (camera) showMotion(camera); break;
      // on the camera's page the ended view says it; elsewhere, a toast
      case "saving": if ($("#session").classList.contains("hidden")) toast("Saving the recording…"); break;
    }
  };
  ws.onclose = () => setTimeout(connect, 1500);
}

connect();
scan();
