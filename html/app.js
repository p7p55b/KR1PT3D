// Browser client for C++ SSE E2EE relay

const te = new TextEncoder();
const td = new TextDecoder();

function toB64(bytes) {
  let bin = '';
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}
function fromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
function randBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

class Client {
  constructor() {
    this.room = null;
    this.user = null;
    this.peer = null;
    this.keys = null; // { publicKey, privateKey }
    this.shared = null; // AES-GCM key
    this.es = null; // EventSource
    this.server = location.origin; // same host

    this.ui = this.bindUI();
  }

  bindUI() {
    const ui = {
      room: document.getElementById('room'),
      user: document.getElementById('user'),
      peer: document.getElementById('peer'),
      connect: document.getElementById('connect'),
      status: document.getElementById('status'),
      debug: document.getElementById('debug'),
      log: document.getElementById('log'),
      input: document.getElementById('input'),
      send: document.getElementById('send'),
    };
    ui.connect.addEventListener('click', () => this.connect());
    ui.send.addEventListener('click', () => this.onSend());
    ui.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.onSend();
    });
    return ui;
  }

  setStatus(s) { this.ui.status.textContent = s; }
  logMsg(from, text) {
    const el = document.createElement('div');
    el.className = 'msg';
    el.innerHTML = `<span class="from">${from}:</span>${text}`;
    this.ui.log.appendChild(el);
    this.ui.log.scrollTop = this.ui.log.scrollHeight;
  }
  debug(obj) { this.ui.debug.textContent = JSON.stringify(obj, null, 2); }

  async connect() {
    try {
      if (!window.isSecureContext) {
        console.warn('Web Crypto recommande HTTPS ou localhost.');
      }
      if (!crypto?.subtle) throw new Error('crypto.subtle non disponible');

      this.room = this.ui.room.value.trim() || 'demo-room';
      this.user = this.ui.user.value.trim();
      this.peer = this.ui.peer.value.trim();
      if (!this.user || !this.peer) throw new Error('Renseignez user et peer');

      this.setStatus('Génération des clés…');
      this.keys = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey']
      );
      const pubRaw = await crypto.subtle.exportKey('raw', this.keys.publicKey);
      const pubB64 = toB64(pubRaw);

      await this.openSSE();

      await fetch(`${this.server}/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room: this.room, user: this.user, pubKeyRawB64: pubB64 }),
      });

      await this.tryDeriveWithPeers();

      this.setStatus('Connecté');
      this.ui.input.disabled = false;
      this.ui.send.disabled = false;
      this.logMsg('Système', 'Connecté. En attente/échange de clé avec le pair.');
    } catch (e) {
      console.error(e);
      this.setStatus(`Erreur: ${e.message}`);
    }
  }

  async openSSE() {
    if (this.es) this.es.close();
    const url = `${this.server}/events?room=${encodeURIComponent(this.room)}&user=${encodeURIComponent(this.user)}`;
    this.es = new EventSource(url);
    this.es.addEventListener('peer-joined', (ev) => {
      const data = JSON.parse(ev.data);
      if (data.user === this.peer) {
        this.debug({ peerJoined: data.user });
        this.tryDeriveWithPeers();
      }
    });
    this.es.addEventListener('message', (ev) => this.onCipherMessage(ev));
    this.es.onerror = (e) => { console.warn('SSE error', e); };
  }

  async tryDeriveWithPeers() {
    const res = await fetch(`${this.server}/peers?room=${encodeURIComponent(this.room)}`);
    const json = await res.json();
    const peerEntry = json.peers.find((p) => p.user === this.peer);
    if (!peerEntry) return;
    await this.deriveShared(peerEntry.pubKeyRawB64);
  }
  async deriveShared(peerPubB64) {
    const peerPubKey = await crypto.subtle.importKey('raw', fromB64(peerPubB64), { name: 'ECDH', namedCurve: 'P-256' }, true, []);
    this.shared = await crypto.subtle.deriveKey(
      { name: 'ECDH', public: peerPubKey }, this.keys.privateKey,
      { name: 'AES-GCM', length: 256 }, false, ['encrypt','decrypt']
    );
    this.logMsg('Système', `Clé de session établie avec ${this.peer}.`);
  }

  async onSend() {
    const text = this.ui.input.value.trim();
    if (!text) return;
    this.ui.input.value = '';
    if (!this.shared) { this.logMsg('Système','En attente de la clé partagée…'); await this.tryDeriveWithPeers(); if (!this.shared) return; }
    const iv = randBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, this.shared, te.encode(text));
    const payload = { ivB64: toB64(iv), ctB64: toB64(ct) };
    await fetch(`${this.server}/send`, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ room:this.room, from:this.user, to:this.peer, payload }) });
    this.logMsg(this.user, text);
  }

  async onCipherMessage(ev) {
    try {
      const msg = JSON.parse(ev.data);
      if (msg.to !== this.user) return;
      if (!this.shared) await this.tryDeriveWithPeers();
      const iv = new Uint8Array(fromB64(msg.payload.ivB64));
      const ct = fromB64(msg.payload.ctB64);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, this.shared, ct);
      const text = td.decode(pt);
      this.logMsg(msg.from, text);
    } catch (e) {
      this.logMsg('Erreur', 'Impossible de déchiffrer un message.');
    }
  }
}

window.addEventListener('DOMContentLoaded', () => { new Client(); });

