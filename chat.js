/* Conversation page for visitors: the secret after "#" in the link unlocks
 * one conversation with the owner. See lib.js for the encryption. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  const say = (el, msg) => { el.textContent = msg || ""; show(el, !!msg); };

  function fail(msg) {
    show($("loading"), false);
    say($("load-error"), msg);
  }

  if (!window.SM) return; // moving to https://
  SM.applyLogo();
  if (!SM.supported) { fail(SM.unsupportedMessage); return; }

  let thread;
  let shown = 0;

  function bubble(m) {
    const li = $("bubble-tpl").content.firstElementChild.cloneNode(true);
    li.classList.add(m.from_owner ? "theirs" : "mine");
    const body = li.querySelector(".plain");
    body.textContent = m.broken ? "This message couldn't be decrypted." : m.text;
    if (m.broken) body.classList.add("broken");
    const time = li.querySelector("time");
    time.dateTime = m.created_at;
    time.textContent = (m.from_owner ? "Reply · " : "You · ") + SM.formatTime(m.created_at);
    return li;
  }

  async function load() {
    const rows = await SM.rpc("get_thread", { thread_token: thread.token });
    if (!rows.length) throw new SM.ApiError("empty", "");
    if (rows.length === shown) return;
    const msgs = await SM.openAll(thread.key, rows);
    $("thread").replaceChildren(...msgs.map(bubble));
    show($("waiting"), !msgs.some((m) => m.from_owner));
    if (msgs.length > shown && shown) $("thread").lastElementChild.scrollIntoView({ behavior: "smooth", block: "nearest" });
    shown = msgs.length;
  }

  (async function start() {
    try {
      thread = await SM.threadFromSecret(location.hash.slice(1));
    } catch (_) {
      fail("This link is broken or incomplete. Check you copied all of it.");
      return;
    }
    try {
      await load();
    } catch (e) {
      fail(e.code === "empty" ? "There's no conversation at this link. It may have been deleted."
        : e.code === "offline" ? e.message : "Couldn't load the conversation. Please try again.");
      return;
    }
    show($("loading"), false);
    show($("chat"), true);
    SM.setupNotifyButton($("notify"), $("notify-note"), "sm-notify-" + thread.id,
      (sub) => SM.rpc("subscribe_thread", { thread_token: thread.token, ...sub }));
    // Title the saved conversation by its first message, unless that one
    // couldn't be decrypted (then keep whatever title it already had).
    const first = $("thread").querySelector(".plain:not(.broken)");
    SM.saveConversation(thread.secret, first && first === $("thread").querySelector(".plain") ? first.textContent : "");
  })();

  // Opening another conversation link in this tab only changes the "#" part,
  // which doesn't reload the page, so reload it ourselves.
  window.addEventListener("hashchange", () => location.reload());

  // Replies appear by themselves: check every few seconds while the page is
  // on screen, and straight away when it comes back on screen.
  let loading = false;
  function poll() {
    if (!thread || !shown || loading || document.hidden) return;
    loading = true;
    load().catch(() => {}).finally(() => { loading = false; });
  }
  setInterval(poll, 3000);
  document.addEventListener("visibilitychange", poll);

  $("refresh").addEventListener("click", async () => {
    const btn = $("refresh");
    btn.disabled = true;
    say($("send-error"), "");
    try { await load(); } catch (e) { say($("send-error"), e.code === "offline" ? e.message : "Couldn't check for replies."); }
    btn.disabled = false;
  });

  $("send").addEventListener("click", async () => {
    const text = $("message").value;
    if (!text.trim()) { say($("send-error"), "Write a message first."); return; }
    say($("send-error"), "");
    const btn = $("send");
    btn.disabled = true;
    btn.textContent = "Sending…";
    try {
      const blob = await SM.sealMessage(thread.key, false, text);
      await SM.rpc("send_to_thread", { thread_token: thread.token, envelope: null, blob });
      $("message").value = "";
      await load();
    } catch (e) {
      say($("send-error"),
        e.message === "too long" ? "That message is too long. Please shorten it."
        : e.code === "offline" ? e.message
        : /too many|full/.test(e.message) ? e.message.charAt(0).toUpperCase() + e.message.slice(1) + "."
        : "Couldn't send your message. Please try again.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Send";
    }
  });

  $("forget").addEventListener("click", () => {
    SM.forgetConversation(thread.secret);
    $("forget").textContent = "Removed ✓ (the link still works)";
    $("forget").disabled = true;
  });
})();
