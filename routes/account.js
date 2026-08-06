const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

router.get("/account", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  const me = db.prepare("SELECT * FROM accounts WHERE username = ?").get(req.cookies.username);
  if (!me) {
    res.clearCookie("username");
    return res.redirect("/");
  }

  const messageBlock = me.message_ciphertext && me.message_iv
    ? `
      <div class="message-box" id="locked-message" data-ciphertext="${me.message_ciphertext}" data-iv="${me.message_iv}">
        <div id="lock-state">🔒 Message locked</div>
        <label for="unlock-password">Password</label>
        <input type="password" id="unlock-password" placeholder="Enter the message password" autofocus>
        <button type="button" id="unlock-button" class="btn btn-yellow">Unlock</button>
        <div id="unlock-status" class="subtitle"></div>
        <div id="unlocked-message" class="message-box empty" style="display:none; white-space: pre-wrap;"></div>
      </div>
    `
    : `<div class="message-box empty">💬 No message set yet.</div>`;

  res.send(page("My Page", `
    <h1>👋 Hi, ${me.display_name}!</h1>
    ${messageBlock}
    <div class="button-row">
      <a href="/set-message" class="btn btn-yellow">✏️ Set My Message</a>
      <a href="/change-password" class="btn btn-green">🔑 Change Password</a>
    </div>
    <a href="/logout" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Log Out</a>
    <script src="/public/crypto.js"></script>
    <script>
      (function () {
        const lockedMessage = document.getElementById("locked-message");
        if (!lockedMessage) {
          return;
        }

        const unlockButton = document.getElementById("unlock-button");
        const passwordInput = document.getElementById("unlock-password");
        const unlockStatus = document.getElementById("unlock-status");
        const unlockedMessage = document.getElementById("unlocked-message");
        const ciphertext = lockedMessage.dataset.ciphertext;
        const iv = lockedMessage.dataset.iv;

        unlockButton.addEventListener("click", async () => {
          unlockStatus.textContent = "Decrypting locally...";

          try {
            const plaintext = await window.ClassmateCrypto.decryptMessage(ciphertext, iv, passwordInput.value);
            unlockedMessage.textContent = plaintext;
            unlockedMessage.style.display = "block";
            unlockStatus.textContent = "";
            lockedMessage.querySelector("#lock-state").textContent = "🔓 Message unlocked";
          } catch (error) {
            unlockStatus.textContent = "Wrong password or corrupted message.";
          }
        });
      })();
    </script>
  `));
});

router.get("/logout", (req, res) => {
  res.clearCookie("username");
  res.redirect("/");
});

module.exports = router;
