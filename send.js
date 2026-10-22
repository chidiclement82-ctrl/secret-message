/* Send page: send a complaint, which starts an encrypted conversation with the owner. See lib.js for
 * the encryption. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  const say = (el, msg) => { el.textContent = msg || ""; show(el, !!msg); };

  if (!window.SM) return; // moving to https://
  if (!SM.supported) {
    say($("send-error"), SM.unsupportedMessage);
    $("send").disabled = true;
    return;
  }

  // Conversations started on this device, newest first.
  function renderSaved() {
    const list = SM.savedConversations();
    show($("saved"), list.length > 0);
    $("saved-list").replaceChildren(...list.map((c) => {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = SM.chatLink(c.secret);
      a.textContent = c.preview || "Conversation";
      const when = document.createElement("span");
      when.className = "hint";
      when.textContent = " · " + SM.formatTime(new Date(c.at).toISOString());
      li.append(a, when);
      return li;
    }));
  }
  renderSaved();
  SM.applyLogo();

  // A reply notification links here with ?open=<thread id>: find that
  // conversation among the ones saved on this device and open it.
  const openId = new URLSearchParams(location.search).get("open");
  if (openId) {
    (async () => {
      for (const c of SM.savedConversations()) {
        if ((await SM.threadFromSecret(c.secret)).id === openId) { location.replace(SM.chatLink(c.secret)); return; }
      }
    })().catch(() => {});
  }

  // Look the key up early, so we can say straight away if the inbox isn't open.
  let keyPromise = SM.ownerPublicKey();
  keyPromise.then((k) => {
    if (!k.publicKey) { show($("compose"), false); show($("closed"), true); }
  }, () => {});

  const message = $("message");
  message.addEventListener("input", () => { $("count").textContent = message.value.length; });

  $("send").addEventListener("click", async () => {
    const text = message.value;
    const name = $("name").value.trim();
    if (!text.trim()) { say($("send-error"), "Write your complaint first."); return; }
    if (!name) { say($("send-error"), "Please write your name."); $("name").focus(); return; }
    say($("send-error"), "");
    const btn = $("send");
    btn.disabled = true;
    btn.textContent = "Sending…";
    try {
      const { publicKey } = await keyPromise.catch(() => (keyPromise = SM.ownerPublicKey()));
      if (!publicKey) { show($("compose"), false); show($("closed"), true); return; }
      const thread = await SM.newThread();
      const blob = await SM.sealMessage(thread.key, false, text, name);
      const envelope = await SM.sealEnvelope(publicKey, thread.id, thread.keyBytes);
      await SM.rpc("send_to_thread", { thread_token: thread.token, envelope, blob });

      SM.saveConversation(thread.secret, text.trim());
      const link = SM.chatLink(thread.secret);
      $("chat-link").value = link;
      $("open-chat").href = link;
      message.value = "";
      $("name").value = "";
      $("count").textContent = "0";
      show($("compose"), false);
      show($("sent"), true);
      renderSaved();
    } catch (e) {
      say($("send-error"),
        e.message === "too long" ? "That complaint is too long. Please shorten it."
        : e.code === "offline" ? e.message
        : e.code === "key-mismatch" ? "Something is wrong with this inbox's key, so the message was not sent."
        : /too many/.test(e.message) ? "Lots of messages are arriving right now. Please try again in a minute."
        : "Couldn't send your complaint. Please try again.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Send";
    }
  });

  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("chat-link").value);
      $("copy").textContent = "Copied ✓";
      setTimeout(() => { $("copy").textContent = "Copy"; }, 1500);
    } catch (_) {
      $("chat-link").select();
    }
  });

  $("again").addEventListener("click", () => {
    show($("sent"), false);
    show($("compose"), true);
    message.focus();
  });
})();
