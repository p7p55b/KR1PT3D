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

const REPLY_ICON = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px"><polyline points="9 10 4 15 9 20"></polyline><path d="M4 15h11a4 4 0 0 0 0-8h-1"></path></svg>';

function newId() {
  return (crypto.randomUUID) ? crypto.randomUUID() : toB64(randBytes(16));
}

function truncate(s, n) {
  s = String(s);
  return s.length > n ? s.slice(0, n) + '…' : s;
}

function escapeHtml(s) {
  const div = document.createElement('div');
  div.textContent = String(s);
  return div.innerHTML;
}

function formatMarkdown(rawText) {
  let s = escapeHtml(rawText);

  s = s.replace(/```([\s\S]*?)```/g, (m, code) => `<pre class="md-pre"><code>${code.trim()}</code></pre>`);
  s = s.replace(/`([^`\n]+)`/g, '<code class="md-code">$1</code>');
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/__([^_]+)__/g, '<strong>$1</strong>');
  s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  s = s.replace(/_([^_]+)_/g, '<em>$1</em>');
  s = s.replace(/~~([^~]+)~~/g, '<del>$1</del>');
  s = s.replace(/^&gt;\s?(.*)$/gm, '<blockquote class="md-quote">$1</blockquote>');
  s = s.replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" class="md-link">$1</a>');

  s = s.replace(/(https?:\/\/[^\s<]+?\.(?:gif|png|jpe?g|webp)(?:\?[^\s<]*)?)/gi, (url) => {
    return `<div class="chat-embed-blocked" data-src="${url}">` +
      `<span class="embed-warning">[ Media distant - Cliquer pour charger (expose votre IP à l'hôte) ]</span>` +
      `</div>`;
  });

  s = s.replace(/(^|[\s(])(https?:\/\/[^\s<]+)/g, (m, pre, url) => {
    if (url.match(/\.(gif|png|jpe?g|webp)/i)) return m;
    return `${pre}<a href="${url}" target="_blank" rel="noopener noreferrer" class="md-link">${url}</a>`;
  });

  s = s.replace(/\n/g, '<br>');
  return s;
}

class Client {
  constructor() {
    this.room = null;
    this.user = null;
    this.peer = null;
    this.keys = null;
    this.sharedKeys = new Map();
    this.peerPubKeys = new Map();
    this.peers = new Map();
    this.es = null;
    this.server = location.origin;
    this.pubB64 = null;
    this.isConnected = false;
    this.lastHeartbeat = Date.now();
    this.reconnectTimer = null;
    this.syncInterval = null;
    this.heartbeatWatchdog = null;

    this.messages = new Map();
    this.replyingTo = null;
    this.baseTitle = document.title;
    this.unreadCount = 0;

    this.activeChat = 'general';
    this.conversations = new Map();
    this.openDMs = new Set();
    this.unreadGeneral = 0;
    this.unreadDMs = new Map();
    this._roomKeys = new Map();
    this.searchQuery = '';

    this.ui = this.bindUI();
    this.setupNotifications();
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
      replyPreview: document.getElementById('reply-preview'),
      replyPreviewText: document.getElementById('reply-preview-text'),
      replyCancel: document.getElementById('reply-cancel'),
      channelGeneral: document.getElementById('channel-general'),
      generalUnread: document.getElementById('general-unread'),
      activeChatIcon: document.getElementById('active-chat-icon'),
      activeChatTitle: document.getElementById('active-chat-title'),
      activeChatDesc: document.getElementById('active-chat-desc'),
      backToGeneralBtn: document.getElementById('back-to-general-btn'),
      dmsList: document.getElementById('dms-list'),
      dmsCount: document.getElementById('dms-count'),
      searchUser: document.getElementById('search-user'),
      peersList: document.getElementById('peers-list'),
      peersCount: document.getElementById('peers-count'),
      stickerBtn: document.getElementById('sticker-btn'),
      stickerPanel: document.getElementById('sticker-panel'),
      gifUrlInput: document.getElementById('gif-url-input'),
      gifInsertBtn: document.getElementById('gif-insert-btn'),
    };

    if (ui.channelGeneral) {
      ui.channelGeneral.addEventListener('click', () => this.selectChat('general'));
    }
    if (ui.backToGeneralBtn) {
      ui.backToGeneralBtn.addEventListener('click', () => this.selectChat('general'));
    }
    if (ui.searchUser) {
      ui.searchUser.addEventListener('input', () => {
        this.searchQuery = ui.searchUser.value.trim().toLowerCase();
        this.renderOnlinePeers();
      });
      ui.searchUser.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          this.onSearchSubmit();
        }
      });
    }

    ui.connect.addEventListener('click', () => {
      if (this.isConnected) {
        this.disconnect();
      } else {
        this.connect();
      }
    });
    const handleLeave = () => {
      if (this.isConnected) {
        this.disconnect(true);
      }
    };
    window.addEventListener('beforeunload', handleLeave);
    window.addEventListener('pagehide', handleLeave);
    ui.send.addEventListener('click', () => this.onSend());

    ui.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        this.onSend();
      }
    });

    ui.input.addEventListener('input', () => {
      ui.input.style.height = 'auto';
      ui.input.style.height = Math.min(ui.input.scrollHeight, 140) + 'px';
    });

    ui.replyCancel.addEventListener('click', () => this.cancelReply());

    ui.log.addEventListener('click', (e) => {
      const blocked = e.target.closest('.chat-embed-blocked');
      if (blocked && blocked.dataset.src) {
        const url = blocked.dataset.src;
        blocked.outerHTML = `<a href="${url}" target="_blank" rel="noopener noreferrer" class="chat-embed-link"><img src="${url}" class="chat-embed-img" loading="lazy" alt="embed" /></a>`;
        return;
      }

      const btn = e.target.closest('.reply-btn');
      if (!btn) return;
      const id = btn.dataset.target;
      this.startReply(id);
    });

    if (ui.stickerBtn && ui.stickerPanel) {
      ui.stickerBtn.addEventListener('click', () => this.toggleStickerPanel());

      document.querySelectorAll('.sticker-item').forEach((btn) => {
        btn.addEventListener('click', () => {
          const text = btn.dataset.text;
          if (text) {
            this.insertTextAtCursor(text);
            this.toggleStickerPanel();
          }
        });
      });

      if (ui.gifInsertBtn && ui.gifUrlInput) {
        ui.gifInsertBtn.addEventListener('click', () => {
          const url = ui.gifUrlInput.value.trim();
          if (url) {
            this.insertTextAtCursor(url);
            ui.gifUrlInput.value = '';
            this.toggleStickerPanel();
          }
        });
      }
    }

    ui.peer.addEventListener('input', () => {
      this.peer = ui.peer.value.trim();
      this.renderPeers();
    });

    return ui;
  }

  setupNotifications() {
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.clearNotifications();
        if (this.user && this.room) this.fetchPeers();
      }
    });
    window.addEventListener('focus', () => {
      this.clearNotifications();
      if (this.user && this.room) this.fetchPeers();
    });
  }

  notifyUnread() {
    if (document.hidden) {
      this.unreadCount++;
      document.title = `(•) ${this.baseTitle}`;
    }
  }

  clearNotifications() {
    this.unreadCount = 0;
    document.title = this.baseTitle;
  }

  toggleStickerPanel() {
    if (!this.ui.stickerPanel) return;
    const isVisible = this.ui.stickerPanel.style.display !== 'none';
    this.ui.stickerPanel.style.display = isVisible ? 'none' : 'flex';
    if (!isVisible && this.ui.gifUrlInput) {
      this.ui.gifUrlInput.focus();
    }
  }

  insertTextAtCursor(text) {
    const input = this.ui.input;
    const start = input.selectionStart || 0;
    const end = input.selectionEnd || 0;
    const val = input.value;
    input.value = val.slice(0, start) + text + val.slice(end);
    input.selectionStart = input.selectionEnd = start + text.length;
    input.style.height = 'auto';
    input.style.height = Math.min(input.scrollHeight, 140) + 'px';
    input.focus();
  }

  setStatus(s) {
    this.ui.status.textContent = s;
  }

  startReply(id) {
    const original = this.messages.get(id);
    if (!original) return;
    this.replyingTo = { id: original.id, from: original.from, text: original.text };
    this.ui.replyPreviewText.innerHTML = `${REPLY_ICON} ${escapeHtml(original.from)} : ${escapeHtml(truncate(original.text, 60))}`;
    this.ui.replyPreview.style.display = 'flex';
    this.ui.input.focus();
  }

  cancelReply() {
    this.replyingTo = null;
    this.ui.replyPreview.style.display = 'none';
  }

  getConversation(chatId) {
    const id = chatId || 'general';
    if (!this.conversations.has(id)) {
      this.conversations.set(id, []);
    }
    return this.conversations.get(id);
  }

  createMessageElement(msg) {
    const el = document.createElement('div');
    el.className = 'msg';
    el.dataset.id = msg.id;

    const body = document.createElement('div');
    body.className = 'msg-body';

    if (msg.replyTo) {
      const quote = document.createElement('div');
      quote.className = 'msg-reply-quote';
      quote.innerHTML = `${REPLY_ICON} ${escapeHtml(msg.replyTo.from)} : ${escapeHtml(truncate(msg.replyTo.text, 60))}`;
      quote.title = 'Aller au message original';
      quote.addEventListener('click', () => {
        const target = this.ui.log.querySelector(`[data-id="${msg.replyTo.id}"]`);
        if (target) target.scrollIntoView({ block: 'center', behavior: 'smooth' });
      });
      body.appendChild(quote);
    }

    const content = document.createElement('div');
    content.className = 'msg-content';

    const isSystemMessage = msg.from === 'Système' || msg.from === 'Erreur';
    if (!isSystemMessage && msg.from !== this.user) {
      content.classList.add('peer');
    }

    const from = document.createElement('span');
    from.className = 'from';
    from.textContent = `${msg.from}:`;
    content.appendChild(from);

    const textSpan = document.createElement('span');
    if (isSystemMessage) {
      textSpan.textContent = msg.text;
    } else {
      textSpan.innerHTML = formatMarkdown(msg.text);
    }
    content.appendChild(textSpan);

    body.appendChild(content);
    el.appendChild(body);

    if (!isSystemMessage) {
      const btn = document.createElement('button');
      btn.className = 'reply-btn';
      btn.dataset.target = msg.id;
      btn.innerHTML = REPLY_ICON;
      btn.title = 'Répondre';
      el.appendChild(btn);
    }

    return el;
  }

  logMsg(chatId, msg) {
    const id = chatId || 'general';
    this.messages.set(msg.id, msg);
    const list = this.getConversation(id);
    list.push(msg);

    if (this.activeChat === id) {
      const el = this.createMessageElement(msg);
      this.ui.log.appendChild(el);
      this.ui.log.scrollTop = this.ui.log.scrollHeight;
    } else {
      if (id === 'general') {
        this.unreadGeneral++;
      } else {
        const count = this.unreadDMs.get(id) || 0;
        this.unreadDMs.set(id, count + 1);
      }
      this.renderPeers();
    }

    if (!msg.isSystem && msg.from !== this.user && msg.from !== 'Système' && msg.from !== 'Erreur') {
      this.notifyUnread();
    }
  }

  renderCurrentMessages() {
    this.ui.log.innerHTML = '';
    const list = this.getConversation(this.activeChat);
    list.forEach((msg) => {
      const el = this.createMessageElement(msg);
      this.ui.log.appendChild(el);
    });
    this.ui.log.scrollTop = this.ui.log.scrollHeight;
  }

  logSystem(from, text) {
    this.logMsg(this.activeChat, { id: newId(), from, text, replyTo: null, isSystem: true });
  }

  async selectChat(chatId) {
    const target = chatId || 'general';
    this.activeChat = target;
    if (this.ui.peer) {
      this.ui.peer.value = (target === 'general') ? '' : target;
    }
    this.peer = (target === 'general') ? null : target;

    if (target !== 'general') {
      this.openDMs.add(target);
    }

    if (target === 'general') {
      this.unreadGeneral = 0;
    } else {
      this.unreadDMs.delete(target);
    }

    this.cancelReply();
    this.renderActiveChatHeader();
    this.renderPeers();
    this.renderCurrentMessages();

    if (target !== 'general') {
      await this.getSharedKey(target);
    }
    if (this.isConnected && this.ui.input) {
      this.ui.input.focus();
    }
  }

  openAndSelectDM(peerUser) {
    if (!peerUser || peerUser === this.user) return;
    this.openDMs.add(peerUser);
    this.selectChat(peerUser);
  }

  closeDM(peerUser, ev) {
    if (ev) ev.stopPropagation();
    this.openDMs.delete(peerUser);
    if (this.activeChat === peerUser) {
      this.selectChat('general');
    } else {
      this.renderDMsList();
    }
  }

  onSearchSubmit() {
    const q = this.searchQuery;
    if (!q) return;

    const peers = Array.from(this.peers.values()).filter((p) => p.online !== false && p.user !== this.user);
    const exact = peers.find((p) => p.user.toLowerCase() === q);
    const partial = peers.find((p) => p.user.toLowerCase().includes(q));
    const target = exact || partial;

    if (target) {
      this.openAndSelectDM(target.user);
      if (this.ui.searchUser) this.ui.searchUser.value = '';
      this.searchQuery = '';
      this.renderOnlinePeers();
    } else {
      this.logSystem('Système', `Aucun utilisateur en ligne correspondant à "${q}".`);
    }
  }

  renderActiveChatHeader() {
    if (!this.ui.activeChatTitle) return;
    if (this.activeChat === 'general') {
      if (this.ui.activeChatIcon) this.ui.activeChatIcon.textContent = '';
      this.ui.activeChatTitle.textContent = 'Salon Général';
      if (this.ui.activeChatDesc) {
        this.ui.activeChatDesc.textContent = `Discussion publique de la room "${this.room || 'demo-room'}"`;
      }
      if (this.ui.backToGeneralBtn) this.ui.backToGeneralBtn.style.display = 'none';
      if (this.ui.input) this.ui.input.placeholder = 'Message dans #général (Shift+Enter pour saut de ligne)…';
    } else {
      if (this.ui.activeChatIcon) this.ui.activeChatIcon.textContent = '';
      this.ui.activeChatTitle.textContent = `Message Privé : ${this.activeChat}`;
      if (this.ui.activeChatDesc) {
        this.ui.activeChatDesc.textContent = `Chiffré E2EE direct (uniquement vous et ${this.activeChat})`;
      }
      if (this.ui.backToGeneralBtn) this.ui.backToGeneralBtn.style.display = 'inline-block';
      if (this.ui.input) this.ui.input.placeholder = `Message privé à ${this.activeChat}…`;
    }
  }

  async getRoomKey(roomId) {
    const id = roomId || 'default';
    if (this._roomKeys.has(id)) {
      return this._roomKeys.get(id);
    }
    const raw = te.encode(`kr1pt3d:room-general:${id}`);
    const hash = await crypto.subtle.digest('SHA-256', raw);
    const key = await crypto.subtle.importKey(
      'raw',
      hash,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
    this._roomKeys.set(id, key);
    return key;
  }

  debug(obj) {
    this.ui.debug.textContent = JSON.stringify(obj, null, 2);
  }

  async getOrCreateKeys(room, user) {
    try {
      Object.keys(localStorage).filter((k) => k.startsWith('kr1pt3d_')).forEach((k) => localStorage.removeItem(k));
    } catch (_) {}

    if (window.BroadcastChannel) {
      const channelName = `kr1pt3d_ephemeral_${encodeURIComponent(room)}`;
      const bc = new BroadcastChannel(channelName);

      const sharedFromTab = await new Promise((resolve) => {
        const timer = setTimeout(() => resolve(null), 90);
        const onMsg = async (e) => {
          if (e.data && e.data.type === 'response_key' && e.data.user === user) {
            clearTimeout(timer);
            bc.removeEventListener('message', onMsg);
            try {
              const privateKey = await crypto.subtle.importKey(
                'jwk',
                e.data.privateJwk,
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                ['deriveKey']
              );
              const publicKey = await crypto.subtle.importKey(
                'raw',
                fromB64(e.data.pubB64),
                { name: 'ECDH', namedCurve: 'P-256' },
                true,
                []
              );
              resolve({ keys: { privateKey, publicKey }, pubB64: e.data.pubB64 });
            } catch (_) {
              resolve(null);
            }
          }
        };
        bc.addEventListener('message', onMsg);
        bc.postMessage({ type: 'request_key', user });
      });

      if (sharedFromTab) {
        this.setupKeySharing(bc, user, sharedFromTab.keys, sharedFromTab.pubB64);
        return sharedFromTab;
      }
    }

    const keys = await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveKey']
    );
    const pubRaw = await crypto.subtle.exportKey('raw', keys.publicKey);
    const pubB64 = toB64(pubRaw);

    if (window.BroadcastChannel) {
      const channelName = `kr1pt3d_ephemeral_${encodeURIComponent(room)}`;
      const bc = new BroadcastChannel(channelName);
      this.setupKeySharing(bc, user, keys, pubB64);
    }

    return { keys, pubB64 };
  }

  async setupKeySharing(bc, user, keys, pubB64) {
    try {
      const privateJwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
      bc.addEventListener('message', (e) => {
        if (e.data && e.data.type === 'request_key' && e.data.user === user) {
          bc.postMessage({ type: 'response_key', user, pubB64, privateJwk });
        }
      });
    } catch (_) {}
  }

  async connect() {
    try {
      if (!window.isSecureContext || !window.crypto?.subtle) {
        throw new Error("crypto.subtle indisponible : HTTPS est obligatoire sur mobile. Veuillez accéder via https:// (et non http://).");
      }

      this.room = this.ui.room.value.trim() || 'demo-room';
      this.user = this.ui.user.value.trim();

      if (!this.user) throw new Error("Veuillez renseigner un nom d'utilisateur (Username)");

      this.setStatus('Connexion au réseau…');
      this.ui.connect.disabled = true;

      const { keys, pubB64 } = await this.getOrCreateKeys(this.room, this.user);
      this.keys = keys;
      this.pubB64 = pubB64;

      await this.openSSE();
      await this.registerKey();
      await this.fetchPeers();

      this.startHeartbeatWatchdog();

      this.isConnected = true;
      this.ui.connect.disabled = false;
      this.ui.connect.textContent = 'Déconnexion';
      this.ui.room.disabled = true;
      this.ui.user.disabled = true;
      this.ui.input.disabled = false;
      this.ui.send.disabled = false;
      if (this.ui.stickerBtn) this.ui.stickerBtn.disabled = false;

      this.setStatus('En ligne');
      await this.selectChat('general');

      this.logSystem('Système', `Connecté en tant que "${this.user}" dans la room "${this.room}". Bienvenue dans le Salon Général !`);
    } catch (e) {
      console.error(e);
      this.isConnected = false;
      this.ui.connect.disabled = false;
      this.ui.connect.textContent = 'Connect to network';
      this.setStatus(`Erreur: ${e.message}`);
    }
  }

  async disconnect(isUnloading = false) {
    const prevRoom = this.room;
    const prevUser = this.user;

    if (prevRoom && prevUser) {
      try {
        const payload = JSON.stringify({ room: prevRoom, user: prevUser });
        if (isUnloading && navigator.sendBeacon) {
          navigator.sendBeacon(`${this.server}/leave`, new Blob([payload], { type: 'application/json' }));
        } else {
          fetch(`${this.server}/leave`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: payload,
            keepalive: true,
          }).catch(() => {});
        }
      } catch (_) {}
    }

    if (this.es) {
      try { this.es.close(); } catch (_) {}
      this.es = null;
    }
    clearTimeout(this.reconnectTimer);
    if (this.heartbeatWatchdog) clearInterval(this.heartbeatWatchdog);
    if (this.syncInterval) clearInterval(this.syncInterval);

    this.isConnected = false;
    this.peers.clear();
    this.peerPubKeys.clear();
    this.sharedKeys.clear();
    this.conversations.clear();
    this.openDMs.clear();
    this.searchQuery = '';
    if (this.ui.searchUser) this.ui.searchUser.value = '';
    this.unreadDMs.clear();
    this.unreadGeneral = 0;
    this.activeChat = 'general';

    if (!isUnloading) {
      this.ui.connect.disabled = false;
      this.ui.connect.textContent = 'Connect to network';
      this.ui.room.disabled = false;
      this.ui.user.disabled = false;
      this.ui.input.disabled = true;
      this.ui.send.disabled = true;
      if (this.ui.stickerBtn) this.ui.stickerBtn.disabled = true;
      this.setStatus('Offline');
      this.renderActiveChatHeader();
      this.renderCurrentMessages();
      this.renderPeers();
      this.logSystem('Système', 'Vous vous êtes déconnecté du réseau.');
    }
  }

  async registerKey() {
    if (!this.room || !this.user || !this.pubB64) return;
    try {
      await fetch(`${this.server}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room: this.room, user: this.user, pubKeyRawB64: this.pubB64 }),
      });
    } catch (e) {
      console.warn('Erreur register:', e);
    }
  }

  async openSSE() {
    if (this.es) {
      try { this.es.close(); } catch (_) {}
      this.es = null;
    }
    clearTimeout(this.reconnectTimer);

    const url = `${this.server}/events?room=${encodeURIComponent(this.room)}&user=${encodeURIComponent(this.user)}`;
    this.es = new EventSource(url);
    this.lastHeartbeat = Date.now();

    this.es.onopen = async () => {
      this.setStatus('Connecté');
      this.lastHeartbeat = Date.now();
      if (this.pubB64) {
        await this.registerKey();
      }
      await this.fetchPeers();
    };

    this.es.addEventListener('ping', () => {
      this.lastHeartbeat = Date.now();
    });

    this.es.addEventListener('peers-sync', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (Array.isArray(data.peers)) {
          const liveUsernames = new Set(data.peers.map((p) => p.user));
          for (const u of Array.from(this.peers.keys())) {
            if (!liveUsernames.has(u) || u === this.user) {
              this.peers.delete(u);
              this.peerPubKeys.delete(u);
              this.sharedKeys.delete(u);
            }
          }
          data.peers.forEach((p) => {
            if (p.user === this.user) return;
            this.peers.set(p.user, { user: p.user, pubKeyRawB64: p.pubKeyRawB64, online: true });
            if (p.pubKeyRawB64) {
              this.peerPubKeys.set(p.user, p.pubKeyRawB64);
            }
          });
          this.renderPeers();
        }
      } catch (_) {}
    });

    this.es.addEventListener('peer-joined', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        this.onPeerJoined(data.user, data.pubKeyRawB64, data.online);
      } catch (_) {}
    });

    this.es.addEventListener('peer-left', (ev) => {
      try {
        const data = JSON.parse(ev.data);
        this.onPeerLeft(data.user);
      } catch (_) {}
    });

    this.es.addEventListener('message', (ev) => this.onCipherMessage(ev));

    this.es.onerror = (e) => {
      console.warn('SSE error', e);
      if (this.es && this.es.readyState === EventSource.CONNECTING) {
        this.setStatus('Reconnexion…');
      } else if (this.es && this.es.readyState === EventSource.CLOSED) {
        this.setStatus('Déconnecté - Reconnexion…');
        this.scheduleReconnect();
      }
    };
  }

  scheduleReconnect() {
    clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => {
      if (this.user && this.room) {
        this.openSSE();
      }
    }, 2500);
  }

  startHeartbeatWatchdog() {
    if (this.heartbeatWatchdog) clearInterval(this.heartbeatWatchdog);
    if (this.syncInterval) clearInterval(this.syncInterval);

    this.heartbeatWatchdog = setInterval(() => {
      if (!this.user || !this.room) return;
      if (Date.now() - this.lastHeartbeat > 35000) {
        console.warn('Flux SSE inactif depuis >35s (perte Zero Trust). Reconnexion active…');
        this.lastHeartbeat = Date.now();
        this.openSSE();
      }
    }, 10000);

    this.syncInterval = setInterval(() => {
      if (this.user && this.room && this.es && this.es.readyState === EventSource.OPEN) {
        this.fetchPeers();
      }
    }, 10000);
  }

  async fetchPeers() {
    try {
      const res = await fetch(`${this.server}/peers?room=${encodeURIComponent(this.room)}`);
      const json = await res.json();
      const liveUsernames = new Set((json.peers || []).map((p) => p.user));
      for (const u of Array.from(this.peers.keys())) {
        if (!liveUsernames.has(u) || u === this.user) {
          this.peers.delete(u);
          this.peerPubKeys.delete(u);
          this.sharedKeys.delete(u);
        }
      }
      (json.peers || []).forEach((p) => {
        if (p.user === this.user) return;
        this.peers.set(p.user, {
          user: p.user,
          pubKeyRawB64: p.pubKeyRawB64 || null,
          online: true,
        });
        if (p.pubKeyRawB64) {
          this.peerPubKeys.set(p.user, p.pubKeyRawB64);
        }
      });
      this.renderPeers();

      if (this.peer && this.peerPubKeys.has(this.peer)) {
        await this.getSharedKey(this.peer);
      }
    } catch (err) {
      console.warn('Erreur récupération peers:', err);
    }
  }

  onPeerJoined(user, pubKeyRawB64, online = true) {
    if (user === this.user) return;
    if (online === false) {
      this.onPeerLeft(user);
      return;
    }
    const existing = this.peers.get(user) || {};
    const finalKey = pubKeyRawB64 || existing.pubKeyRawB64 || null;
    const pubKeyChanged = existing.pubKeyRawB64 && finalKey && existing.pubKeyRawB64 !== finalKey;

    this.peers.set(user, { user, pubKeyRawB64: finalKey, online: true });
    if (finalKey) {
      this.peerPubKeys.set(user, finalKey);
      if (pubKeyChanged) {
        this.sharedKeys.delete(user);
      }
    }
    this.renderPeers();

    if (user === this.peer && finalKey) {
      this.getSharedKey(user);
    }
  }

  onPeerLeft(user) {
    if (this.peers.has(user)) {
      this.peers.delete(user);
      this.peerPubKeys.delete(user);
      this.sharedKeys.delete(user);
      this.unreadDMs.delete(user);

      if (this.activeChat === user) {
        this.logSystem('Système', `${user} s'est déconnecté et a quitté le réseau.`);
      }
      this.renderPeers();
    }
  }

  renderPeers() {
    this.renderChannelGeneral();
    this.renderDMsList();
    this.renderOnlinePeers();
  }

  renderChannelGeneral() {
    if (this.ui.channelGeneral) {
      const isGeneralActive = (this.activeChat === 'general');
      this.ui.channelGeneral.classList.toggle('active', isGeneralActive);
    }
    if (this.ui.generalUnread) {
      if (this.unreadGeneral > 0) {
        this.ui.generalUnread.textContent = String(this.unreadGeneral);
        this.ui.generalUnread.style.display = 'inline-block';
      } else {
        this.ui.generalUnread.style.display = 'none';
      }
    }
  }

  renderDMsList() {
    if (!this.ui.dmsList) return;

    if (!this.isConnected) {
      this.ui.dmsList.innerHTML = '<div class="empty-peers">Non connecté au réseau</div>';
      if (this.ui.dmsCount) this.ui.dmsCount.textContent = '0';
      return;
    }

    const openList = Array.from(this.openDMs);
    if (this.ui.dmsCount) this.ui.dmsCount.textContent = `${openList.length}`;

    this.ui.dmsList.innerHTML = '';
    if (openList.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-peers';
      empty.textContent = 'Aucun message privé ouvert';
      this.ui.dmsList.appendChild(empty);
      return;
    }

    openList.forEach((dmUser) => {
      const isSelected = dmUser === this.activeChat;
      const isOnline = this.peers.has(dmUser) && this.peers.get(dmUser).online !== false;

      const item = document.createElement('div');
      item.className = 'peer-item' + (isSelected ? ' active' : '');
      item.dataset.user = dmUser;
      item.title = `Conversation privée avec ${dmUser}`;

      const dot = document.createElement('span');
      dot.className = 'peer-dot' + (isOnline ? ' online' : '');
      dot.title = isOnline ? 'En ligne' : 'Hors ligne';

      const name = document.createElement('span');
      name.className = 'peer-name';
      name.textContent = dmUser;

      item.appendChild(dot);
      item.appendChild(name);

      const unreadCount = this.unreadDMs.get(dmUser) || 0;
      if (unreadCount > 0) {
        const badge = document.createElement('span');
        badge.className = 'badge unread-badge';
        badge.textContent = String(unreadCount);
        item.appendChild(badge);
      }

      const closeBtn = document.createElement('button');
      closeBtn.className = 'dm-close-btn';
      closeBtn.textContent = '✕';
      closeBtn.title = 'Fermer cette conversation';
      closeBtn.addEventListener('click', (e) => this.closeDM(dmUser, e));
      item.appendChild(closeBtn);

      item.addEventListener('click', (e) => {
        if (e.target !== closeBtn) {
          this.selectChat(dmUser);
        }
      });

      this.ui.dmsList.appendChild(item);
    });
  }

  renderOnlinePeers() {
    if (!this.ui.peersList) return;

    if (!this.isConnected) {
      this.ui.peersList.innerHTML = '<div class="empty-peers">Non connecté au réseau</div>';
      if (this.ui.peersCount) this.ui.peersCount.textContent = '0';
      return;
    }

    const allOnline = Array.from(this.peers.values()).filter((p) => p.online !== false && p.user !== this.user);
    if (this.ui.peersCount) this.ui.peersCount.textContent = `${allOnline.length}`;

    const q = this.searchQuery;
    const filtered = q
      ? allOnline.filter((p) => p.user.toLowerCase().includes(q))
      : allOnline;

    filtered.sort((a, b) => a.user.localeCompare(b.user));

    this.ui.peersList.innerHTML = '';
    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty-peers';
      empty.textContent = q ? 'Aucun utilisateur trouvé' : 'Aucun pair en ligne';
      this.ui.peersList.appendChild(empty);
      return;
    }

    filtered.forEach((peer) => {
      const isSelected = peer.user === this.activeChat;

      const item = document.createElement('div');
      item.className = 'peer-item' + (isSelected ? ' active' : '');
      item.dataset.user = peer.user;
      item.title = `Démarrer un message privé avec ${peer.user}`;

      const dot = document.createElement('span');
      dot.className = 'peer-dot online';
      dot.title = 'En ligne';

      const name = document.createElement('span');
      name.className = 'peer-name';
      name.textContent = peer.user;

      item.appendChild(dot);
      item.appendChild(name);

      item.addEventListener('click', () => {
        this.openAndSelectDM(peer.user);
      });

      this.ui.peersList.appendChild(item);
    });
  }

  async getSharedKey(peerUser) {
    if (!peerUser) return null;
    if (this.sharedKeys.has(peerUser)) {
      return this.sharedKeys.get(peerUser);
    }

    let pubB64 = this.peerPubKeys.get(peerUser);
    if (!pubB64) {
      await this.fetchPeers();
      pubB64 = this.peerPubKeys.get(peerUser);
    }
    if (!pubB64) return null;

    try {
      const peerPubKey = await crypto.subtle.importKey(
        'raw',
        fromB64(pubB64),
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        []
      );
      const shared = await crypto.subtle.deriveKey(
        { name: 'ECDH', public: peerPubKey },
        this.keys.privateKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      this.sharedKeys.set(peerUser, shared);
      return shared;
    } catch (err) {
      console.warn(`Erreur dérivation clé pour ${peerUser}:`, err);
      return null;
    }
  }

  async onSend() {
    const text = this.ui.input.value.trim();
    if (!text) return;

    const isGeneral = (this.activeChat === 'general');
    const targetRecipient = isGeneral ? 'all' : this.activeChat;

    if (!isGeneral && !targetRecipient) {
      this.logSystem('Système', 'Veuillez sélectionner un correspondant (DM) ou revenir au Salon Général.');
      return;
    }

    let encryptionKey;
    if (isGeneral) {
      encryptionKey = await this.getRoomKey(this.room);
    } else {
      encryptionKey = await this.getSharedKey(targetRecipient);
      if (!encryptionKey) {
        this.logSystem('Système', `En attente de la clé de session avec ${targetRecipient}…`);
        return;
      }
    }

    this.ui.input.value = '';
    this.ui.input.style.height = 'auto';

    const id = newId();
    const replyTo = this.replyingTo;
    const plain = JSON.stringify({ id, text, replyTo, target: targetRecipient });

    const iv = randBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encryptionKey, te.encode(plain));
    const payload = { ivB64: toB64(iv), ctB64: toB64(ct) };

    try {
      const resp = await fetch(`${this.server}/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ room: this.room, from: this.user, to: targetRecipient, payload }),
      });
      const result = await resp.json().catch(() => ({}));
      if (!resp.ok || result.ok === false) {
        this.logSystem('Erreur', result.error || 'Destinataire hors ligne, message non délivré.');
        return;
      }
    } catch (e) {
      this.logSystem('Erreur', 'Impossible de contacter le serveur.');
      return;
    }

    this.logMsg(this.activeChat, { id, from: this.user, text, replyTo });
    this.cancelReply();
  }

  async onCipherMessage(ev) {
    try {
      const msg = JSON.parse(ev.data);
      const isGeneral = (msg.to === 'all');

      if (!isGeneral && msg.to !== this.user) return;
      if (msg.from === this.user) return;

      let decryptKey;
      let convChatId;
      if (isGeneral) {
        decryptKey = await this.getRoomKey(this.room);
        convChatId = 'general';
      } else {
        this.openDMs.add(msg.from);
        decryptKey = await this.getSharedKey(msg.from);
        convChatId = msg.from;
        if (!decryptKey) {
          this.logMsg(convChatId, {
            id: newId(),
            from: 'Erreur',
            text: `Clé introuvable pour déchiffrer le message privé de ${msg.from}.`,
          });
          return;
        }
      }

      const iv = new Uint8Array(fromB64(msg.payload.ivB64));
      const ct = fromB64(msg.payload.ctB64);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, decryptKey, ct);
      const raw = td.decode(pt);

      let id, text, replyTo;
      try {
        const parsed = JSON.parse(raw);
        id = parsed.id || newId();
        text = parsed.text;
        replyTo = parsed.replyTo || null;
      } catch {
        id = newId();
        text = raw;
        replyTo = null;
      }

      this.logMsg(convChatId, { id, from: msg.from, text, replyTo });
    } catch (e) {
      console.warn('Erreur déchiffrement message:', e);
      this.logSystem('Erreur', 'Impossible de déchiffrer un message.');
    }
  }
}

window.addEventListener('DOMContentLoaded', () => {
  new Client();
});