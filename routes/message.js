const express = require("express");
const router = express.Router();
const db = require("../db");
const { page } = require("../views");

router.get("/set-message", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  res.send(page("Set My Message", `
    <h1>✏️ Set My Message</h1>
    <p class="subtitle">The browser encrypts your message before it is sent.</p>
    <form id="message-form" method="POST" action="/set-message">
      <label>Your message</label>
      <input type="text" id="message-text" placeholder="Say something fun!" required autofocus>
      <label>Password</label>
      <input type="password" id="message-password" placeholder="Enter the password to protect this message" required>
      <input type="hidden" name="ciphertext" id="message-ciphertext">
      <input type="hidden" name="iv" id="message-iv">
      <button type="submit" class="btn btn-yellow">Save Message 💾</button>
    </form>
    <p id="message-status" class="subtitle"></p>
    <a href="/account" class="btn btn-pink" style="margin-top: 14px; display:inline-block;">Back</a>
    <script src="/public/crypto.js"></script>
    <script>
      (function () {
        const form = document.getElementById("message-form");
        const messageInput = document.getElementById("message-text");
        const passwordInput = document.getElementById("message-password");
        const ciphertextInput = document.getElementById("message-ciphertext");
        const ivInput = document.getElementById("message-iv");
        const status = document.getElementById("message-status");

        form.addEventListener("submit", async (event) => {
          event.preventDefault();
          status.textContent = "Encrypting locally...";

          try {
            const encrypted = await window.ClassmateCrypto.encryptMessage(messageInput.value, passwordInput.value);
            ciphertextInput.value = encrypted.ciphertext;
            ivInput.value = encrypted.iv;
            messageInput.value = "";
            passwordInput.value = "";
            form.submit();
          } catch (error) {
            status.textContent = "Could not encrypt the message. Try again.";
          }
        });
      })();
    </script>
  `));
});

router.post("/set-message", (req, res) => {
  if (!req.cookies.username) {
    return res.redirect("/");
  }

  if (!req.body.ciphertext || !req.body.iv) {
    return res.redirect("/set-message");
  }

  db.prepare("UPDATE accounts SET message_ciphertext = ?, message_iv = ? WHERE username = ?").run(
    req.body.ciphertext,
    req.body.iv,
    req.cookies.username
  );

  res.redirect("/account");
});

module.exports = router;
