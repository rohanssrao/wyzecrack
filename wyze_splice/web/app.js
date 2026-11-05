"use strict";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const mmss = (s) => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
const api = (path, body) => fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {}).then((r) => r.json());

let state = { phase: "idle" };
let saving = false;
let camera = null;

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
  const card = el("div", "cam");
  const thumb = el("div", "thumb", (c.thumb ? `<img src="${esc(c.thumb)}" alt="">` : `<span class="ph">📷</span>`) + `<div class="go">Watch</div>`);
  const body = el("div", "body");
  const name = el("div", "name", `<span>${esc(displayName(c))}</span><button class="edit" title="Rename">✎</button>`);
  const bits = [c.name ? c.model : null, c.ip, c.ready ? "ready" : c.key_known ? "key saved" : null, c.tested ? null : "untested model"].filter(Boolean);
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
  $("#crumb").textContent = "";
  loadLibrary();
}

function showPicker() {
  $("#session").classList.add("hidden");
  $("#picker").classList.remove("hidden");
  $("#crumb").textContent = "";
  resetVideo();
  scan();
}

const STATUS = {
  starting: ["⌁", "spin", "Starting", "Checking the network and the camera."],
  key: ["🔑", "pulse", "Getting the camera's key", "It's read from the camera's own connection to Wyze. This happens once per camera."],
  key_nudge: ["🔑", "pulse", "Getting the camera's key", "The camera is offline for about a minute. When it reconnects, it reports in to Wyze with its key. This happens once per camera."],
  uid: ["🪪", "spin", "Asking Wyze for the camera's ID", "With the camera's own key, the way the camera itself asks."],
  direct: ["⚡", "spin", "Connecting to the camera", "Straight over your network; nothing is rerouted."],
  onpath: ["⇄", "spin", "Getting on the camera's path", "Only this camera is rerouted through this computer; everything else on the network is untouched."],
  enr: ["🔑", "pulse", "Waiting for the camera's key", "The camera sends it to Wyze when it sees motion. Walk in front of it (or wave at it) to speed this up. This only happens once per camera."],
  enr_refused: ["🔒", "bad", "The camera refused our certificate", "This firmware no longer trusts the eMudhra CA, so its key can't be read this way."],
  learning: ["⇄", "spin", "Almost ready", "Learning the camera's relay paths."],
  waiting: ["📱", "pulse", "Waiting for someone to watch", "Open this camera's live view in the Wyze app from a phone that isn't on this Wi-Fi (on cellular, or anywhere else). The feed shows up here as well."],
  connecting: ["⚡", "spin", "Someone opened the live view", "Joining the stream…"],
  joined: ["⚡", "spin", "Joined", "Waiting for the first picture…"],
  saving: ["💾", "spin", "The viewer left", "Saving the video…"],
  stopping: ["⏻", "spin", "Stopping", "Putting the camera's network back the way it was."],
  stopping_direct: ["⏻", "spin", "Stopping", "Saving the recording."],
  error: ["!", "bad", "Something went wrong", ""],
};

function setStatus(key, extra) {
  const [icon, anim, title, text] = STATUS[key] || STATUS.starting;
  const i = $("#status-icon");
  i.textContent = icon;
  i.className = "status-icon " + anim;
  $("#status-title").textContent = title;
  $("#status-text").textContent = key === "error" ? (state.error || "") : text;
  $("#status-extra").textContent = extra || "";
}

const STEPS = {
  direct: [["enr", "Key"], ["uid", "Camera ID"], ["live", "Live"]],
  splice: [["onpath", "On path"], ["enr", "Key"], ["watch", "Viewer"]],
};
let stepsMode = null;

function renderSteps(mode) {
  if (mode === stepsMode) return;
  stepsMode = mode;
  $("#steps").innerHTML = STEPS[mode].map(([k, label]) => `<li data-step="${k}">${label}</li>`).join("");
}

function applyState(s) {
  const prev = state.phase;
  state = s;
  if (s.phase === "idle") {
    if (!$("#session").classList.contains("hidden") && prev !== "idle") showPicker();
    return;
  }
  if (s.camera && $("#session").classList.contains("hidden")) showSession(s.camera);
  const direct = s.mode !== "splice";
  renderSteps(direct ? "direct" : "splice");
  const steps = s.steps || {};
  for (const li of document.querySelectorAll("#steps li")) {
    const st = steps[li.dataset.step];
    li.className = st ? st.status : "";
  }
  const last = document.querySelector('#steps li[data-step="' + (direct ? "live" : "watch") + '"]');
  if (s.phase === "live" || (!direct && s.phase === "connecting")) last.className = "done";
  else if (direct && s.phase === "connecting") last.className = "active";

  let key = s.phase;
  if (s.phase === "starting" && steps.onpath) key = "onpath";
  if (steps.enr && steps.enr.status === "active" && s.phase !== "error") key = direct ? (steps.enr.detail?.nudging ? "key_nudge" : "key") : "enr";
  if (steps.enr && steps.enr.status === "problem") key = "enr_refused";
  if (direct && steps.uid && steps.uid.status === "active") key = "uid";
  if (direct && s.phase === "connecting") key = "direct";
  if (direct && s.phase === "stopping") key = "stopping_direct";
  if (s.phase === "starting" && steps.watch?.detail?.note === "learning") key = "learning";
  if (s.phase === "connecting" && s.session?.state === "joined") key = "joined";
  let extra = "";
  if (key === "enr" || key === "key") { const n = steps.enr.detail?.seen || 0; extra = n ? `${n} camera connection${n > 1 ? "s" : ""} read so far` : ""; }
  if (s.phase === "connecting" && s.session?.state === "failed") extra = "This attempt could not be joined; waiting for the app's retry.";
  if (s.hint === "unplug" && (key === "waiting" || key === "learning")) extra = "One of the camera's connections goes around this computer, so some live views would be missed. Unplug the camera for 5 seconds now (and plug it back in); this page will tell you when it's fixed.";
  else if (key === "waiting" && s.hint === "bypass") extra = "The last live view went around this computer, probably over a connection the camera opened before you started. Unplug the camera for 5 seconds; its new connections will come through here.";
  const stage = $("#stage");
  stage.classList.toggle("is-live", s.phase === "live");
  $("#hud").classList.toggle("hidden", s.phase !== "live");
  if (s.phase !== "live" && !(saving && s.phase === "waiting")) setStatus(key, extra);
  if (s.phase === "live" && prev !== "live") { recStart = (s.session?.since || Date.now() / 1000); $("#stage").classList.remove("dim"); }
  $("#stop").textContent = s.phase === "error" ? "Back" : "Stop";
}

$("#stop").onclick = async () => {
  if (state.phase === "error" || state.phase === "idle") { showPicker(); return; }
  await api("/api/stop", {});
};
$("#quit").onclick = async () => {
  if (!confirm("Quit wyze-splice? Anything it changed on the network is put back.")) return;
  await api("/api/quit", {});
  document.body.innerHTML = `<main><div class="hero"><h1>wyze-splice stopped</h1><p>The network is back to normal. You can close this tab.</p></div></main>`;
};
$("#rescan").onclick = scan;

// ---------------------------------------------------------------- library
async function loadLibrary(fresh) {
  if (!camera) return;
  const lib = await api(`/api/library?mac=${encodeURIComponent(camera.mac)}`);
  const items = [
    ...lib.recordings.map((r) => ({ t: r.started, src: r.video, img: r.thumb, kind: "live", len: mmss(r.seconds) })),
    ...lib.motion.map((m) => ({ t: m.t, src: m.clip, img: m.snapshot, kind: "motion", len: "0:12" })),
  ].sort((a, b) => b.t - a.t);
  const box = $("#saved");
  $("#saved-count").textContent = items.length || "";
  if (!items.length) { box.innerHTML = `<p class="muted">Live views you watch are saved here.</p>`; return; }
  box.innerHTML = "";
  for (const it of items) {
    const t = el("div", "tile" + (fresh && it.src === fresh ? " fresh" : ""));
    const when = new Date(it.t * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
    t.innerHTML = `<div class="img" style="background-image:url('${esc(it.img || "")}')"><span class="pill kind">${it.kind === "live" ? "Live view" : "Motion"}</span><span class="pill len">${it.len}</span><div class="play">▶</div></div><div class="cap">${when}</div>`;
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
let decoder = null, waitKey = true, recStart = null;

function resetVideo(keepLastFrame) {
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = null; waitKey = true;
  $("#stage").classList.remove("is-live");
  if (!keepLastFrame) { $("#stage").classList.remove("dim"); ctx2d.clearRect(0, 0, canvas.width, canvas.height); }
}

function configure(cfg) {
  if (!("VideoDecoder" in window)) {
    setStatus("connecting", "This browser can't decode video (no WebCodecs). The recording is still saved.");
    return;
  }
  if (decoder && decoder.state !== "closed") decoder.close();
  decoder = new VideoDecoder({
    output: (frame) => {
      if (canvas.width !== frame.displayWidth) { canvas.width = frame.displayWidth; canvas.height = frame.displayHeight; }
      ctx2d.drawImage(frame, 0, 0);
      frame.close();
    },
    error: () => { waitKey = true; },
  });
  decoder.configure({ codec: cfg.codec, optimizeForLatency: true });
  waitKey = true;
  if (cfg.width) $("#res").textContent = `${cfg.height}p`;
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
}, 500);

// ---------------------------------------------------------------- socket
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.binaryType = "arraybuffer";
  ws.onmessage = (m) => {
    if (typeof m.data !== "string") {
      const kind = new DataView(m.data).getUint8(0);
      if (kind === 1) onVideo(m.data); else if (kind === 2) onAudio(m.data);
      return;
    }
    const ev = JSON.parse(m.data);
    switch (ev.kind) {
      case "state": applyState(ev); break;
      case "video_config": configure(ev); break;
      case "stats":
        if (ev.height) $("#res").textContent = `${ev.height}p`;
        break;
      case "viewer_left":
        $("#stage").classList.add("dim");
        resetVideo(true);
        if (ev.spliced && ev.had_video) { saving = true; setStatus("saving"); }
        else if (ev.spliced) toast("The camera hung up before sending a picture · waiting for the next try");
        break;
      case "library":
        if (saving) { saving = false; if (state.phase === "waiting") setStatus("waiting"); }
        loadLibrary(ev.new);
        if (ev.new) { toast("Live view saved"); }
        break;
      case "motion":
        toast("Motion detected · clip saved");
        loadLibrary();
        break;
      case "toast": toast(ev.text, ev.level); break;
      case "saving": toast("Saving the recording…"); break;
      case "missed": toast("A live view went around this computer · see the tip above"); break;
    }
  };
  ws.onclose = () => setTimeout(connect, 1500);
}

connect();
scan();
