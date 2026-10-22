/* Send page: encrypt a message to the owner's public key and drop it in the
 * inbox. See lib.js for the encryption. */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const show = (el, on) => { el.hidden = !on; };
  const say = (el, msg) => { el.textContent = msg || ""; show(el, !!msg); };

  if (!SM.supported) {
    say($("send-error"), "This browser can't encrypt. Please use an up-to-date browser.");
    $("send").disabled = true;
    return;
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
    if (!text.trim()) { say($("send-error"), "Write a message first."); return; }
    say($("send-error"), "");
    const btn = $("send");
    btn.disabled = true;
    btn.textContent = "Encrypting…";
    try {
      const { publicKey } = await keyPromise.catch(() => (keyPromise = SM.ownerPublicKey()));
      if (!publicKey) { show($("compose"), false); show($("closed"), true); return; }
      const blob = await SM.sealMessage(publicKey, text, $("from").value.trim());
      btn.textContent = "Sending…";
      await SM.rpc("send_message", { blob });
      message.value = "";
      $("from").value = "";
      $("count").textContent = "0";
      show($("compose"), false);
      show($("sent"), true);
    } catch (e) {
      say($("send-error"),
        e.message === "too long" ? "That message is too long. Please shorten it."
        : e.code === "offline" ? e.message
        : e.code === "key-mismatch" ? "Something is wrong with this inbox's key, so the message was not sent."
        : /too many/.test(e.message) ? "Lots of messages are arriving right now. Please try again in a minute."
        : "Couldn't send your message. Please try again.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Encrypt & send";
    }
  });

  $("again").addEventListener("click", () => {
    show($("sent"), false);
    show($("compose"), true);
    message.focus();
  });
})();
