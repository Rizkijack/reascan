// reascan soundtrack - original generative ambient, Web Audio, zero assets.
//
// There is no audio file and no sample anywhere in this repo: every pad note,
// arpeggio and echo tail is synthesized at runtime from oscillator nodes. That
// means no third-party recording, no license to track, and no extra network
// request on a production page.
//
// Browsers block sound until a user gesture, so the soundtrack is off by
// default and starts only from the fixed SOUND control (or another explicit
// click). The graph is deliberately small: a detuned pad through a slow
// low-pass filter, a sparse triangle arpeggio, and one feedback delay for the
// room. Tab hiding suspends the context; stopping fades to silence before
// suspending, never cuts a click.

const CHORDS = [
  [50, 57, 62, 65], // Dm add9
  [46, 53, 58, 62], // Bb maj7
  [41, 48, 53, 57], // F maj9
  [45, 52, 57, 60], // Am7
];
const ARP_PATTERN = [0, 2, 1, 3, 2, 0, 3, 1];
const CHORD_MS = 14000;
const ARP_MS = 560;
const MASTER_LEVEL = 0.875; // 0.35 x 2.5 after the first listening pass
const PAD_LEVEL = 0.035;
const ARP_LEVEL = 0.03;

let ctx = null;
let master = null;
let padFilter = null;
let spaceSend = null;
let delay = null;
let feedback = null;
let pad = null;
let padIndex = 0;
let arpStep = 0;
let chordTimer = 0;
let arpTimer = 0;
let suspendTimer = 0;
let enabled = false;
let starting = false;
let supported = true;
let button = null;
let label = null;

export function midiToHz(midi) {
  return 440 * Math.pow(2, (midi - 69) / 12);
}

function ignore(promise) {
  if (promise && typeof promise.catch === 'function') promise.catch(() => {});
}

function updateUI() {
  if (!button) return;
  button.classList.toggle('is-on', enabled);
  button.setAttribute('aria-pressed', String(enabled));
  button.setAttribute('aria-label', enabled ? 'Disable ambient soundtrack' : 'Enable ambient soundtrack');
  if (label) label.textContent = enabled ? 'SOUND ON' : 'SOUND OFF';
}

function ensureContext() {
  if (ctx) return ctx;
  if (typeof window === 'undefined') return null;
  const AudioCtx = window.AudioContext || window.webkitAudioContext;
  if (!AudioCtx) {
    supported = false;
    return null;
  }
  try {
    ctx = new AudioCtx();
    master = ctx.createGain();
    master.gain.value = 0.0001;
    master.connect(ctx.destination);

    padFilter = ctx.createBiquadFilter();
    padFilter.type = 'lowpass';
    padFilter.frequency.value = 820;
    padFilter.Q.value = 0.7;
    padFilter.connect(master);

    // Slow filter breathing keeps the pad from sounding like a static organ.
    const lfo = ctx.createOscillator();
    const lfoGain = ctx.createGain();
    lfo.frequency.value = 0.045;
    lfoGain.gain.value = 140;
    lfo.connect(lfoGain);
    lfoGain.connect(padFilter.frequency);
    lfo.start();

    // One shared feedback delay: the pad and the arp both send into it, the
    // dry signal still reaches the master through padFilter/gain.
    delay = ctx.createDelay(1.2);
    delay.delayTime.value = 0.46;
    feedback = ctx.createGain();
    feedback.gain.value = 0.28;
    spaceSend = ctx.createGain();
    spaceSend.gain.value = 0.38;
    padFilter.connect(spaceSend);
    spaceSend.connect(delay);
    delay.connect(feedback);
    feedback.connect(delay);
    delay.connect(master);
    return ctx;
  } catch {
    ctx = null;
    supported = false;
    return null;
  }
}

function schedulePad(now) {
  const chord = CHORDS[padIndex % CHORDS.length];
  padIndex += 1;

  const gain = ctx.createGain();
  gain.gain.value = 0.0001;
  gain.connect(padFilter);
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(PAD_LEVEL, now + 3.2);

  const oscs = [];
  for (const midi of chord) {
    for (const detune of [-6, 6]) {
      const osc = ctx.createOscillator();
      osc.type = 'sine';
      osc.frequency.value = midiToHz(midi);
      osc.detune.value = detune;
      osc.connect(gain);
      osc.start(now);
      oscs.push(osc);
    }
  }

  // Fade the previous chord out under the new one, then stop its oscillators.
  if (pad) {
    const old = pad;
    old.gain.gain.cancelScheduledValues(now);
    old.gain.gain.setValueAtTime(Math.max(old.gain.gain.value, 0.0001), now);
    old.gain.gain.exponentialRampToValueAtTime(0.0001, now + 2.1);
    for (const osc of old.oscs) {
      try { osc.stop(now + 2.2); } catch { /* already stopped */ }
    }
  }
  pad = { gain, oscs };
}

function playArp() {
  if (!enabled || !ctx || ctx.state !== 'running') return;
  const chord = CHORDS[(padIndex - 1 + CHORDS.length) % CHORDS.length] ?? CHORDS[0];
  const midi = chord[ARP_PATTERN[arpStep % ARP_PATTERN.length] % chord.length] + 12;
  arpStep += 1;

  const now = ctx.currentTime + 0.02;
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.type = 'triangle';
  osc.frequency.value = midiToHz(midi);
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(ARP_LEVEL, now + 0.03);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.8);
  osc.connect(gain);
  gain.connect(master);
  gain.connect(spaceSend);
  osc.start(now);
  osc.stop(now + 0.85);
}

export async function startSound() {
  if (starting) return false;
  if (enabled) return true;
  if (!ensureContext()) {
    updateUI();
    return false;
  }

  starting = true;
  if (suspendTimer) {
    clearTimeout(suspendTimer);
    suspendTimer = 0;
  }
  try {
    if (ctx.state === 'suspended' && typeof ctx.resume === 'function') await ctx.resume();
    const now = ctx.currentTime;
    master.gain.cancelScheduledValues(now);
    master.gain.setValueAtTime(Math.max(master.gain.value, 0.0001), now);
    master.gain.exponentialRampToValueAtTime(MASTER_LEVEL, now + 2);

    enabled = true;
    padIndex = 0;
    arpStep = 0;
    schedulePad(now);
    clearInterval(chordTimer);
    clearInterval(arpTimer);
    chordTimer = setInterval(() => { if (enabled) schedulePad(ctx.currentTime); }, CHORD_MS);
    arpTimer = setInterval(playArp, ARP_MS);
    chordTimer.unref?.();
    arpTimer.unref?.();
    updateUI();
    return true;
  } catch {
    enabled = false;
    updateUI();
    return false;
  } finally {
    starting = false;
  }
}

export function stopSound() {
  if (!ctx) return false;
  const wasEnabled = enabled;
  enabled = false;
  clearInterval(chordTimer);
  clearInterval(arpTimer);
  chordTimer = 0;
  arpTimer = 0;

  const now = ctx.currentTime;
  try {
    master.gain.cancelScheduledValues(now);
    master.gain.setValueAtTime(Math.max(master.gain.value, 0.0001), now);
    master.gain.exponentialRampToValueAtTime(0.0001, now + 0.7);

    if (pad) {
      const old = pad;
      pad = null;
      old.gain.gain.cancelScheduledValues(now);
      old.gain.gain.setValueAtTime(Math.max(old.gain.gain.value, 0.0001), now);
      old.gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.7);
      for (const osc of old.oscs) {
        try { osc.stop(now + 0.8); } catch { /* already stopped */ }
      }
    }

    if (suspendTimer) clearTimeout(suspendTimer);
    suspendTimer = setTimeout(() => {
      if (!enabled && ctx && ctx.state === 'running' && typeof ctx.suspend === 'function') {
        ignore(ctx.suspend());
      }
    }, 900);
    suspendTimer.unref?.();
  } catch { /* audio is decorative: never break the page over it */ }

  updateUI();
  return wasEnabled;
}

export async function toggleSound() {
  if (starting) return false;
  if (enabled) {
    stopSound();
    return false;
  }
  return startSound();
}

export function initAudio(root = document) {
  if (button) return true;
  button = root.getElementById?.('sound-toggle') ?? null;
  if (!button) return false;
  label = button.querySelector?.('.sound-label') ?? null;
  if (typeof window === 'undefined') return false;

  supported = Boolean(window.AudioContext || window.webkitAudioContext);
  if (!supported) {
    button.disabled = true;
    button.setAttribute('aria-label', 'Ambient soundtrack unavailable');
    if (label) label.textContent = 'SOUND N/A';
    return false;
  }

  if (button.dataset?.audioWired === 'true') return true;
  if (button.dataset) button.dataset.audioWired = 'true';
  button.addEventListener('click', () => { toggleSound(); });

  document.addEventListener('visibilitychange', () => {
    if (!ctx) return;
    if (document.hidden) {
      if (ctx.state === 'running' && typeof ctx.suspend === 'function') ignore(ctx.suspend());
    } else if (enabled && typeof ctx.resume === 'function') {
      ignore(ctx.resume());
    }
  });

  window.addEventListener?.('beforeunload', () => {
    try { ctx?.close?.(); } catch { /* page is leaving */ }
  }, { once: true });

  updateUI();
  return true;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const boot = () => {
    try { initAudio(); } catch { /* decorative: never block the page */ }
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
}
