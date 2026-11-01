// Caesar cipher demo. All logic runs in the browser; nothing is stored or sent anywhere.
const ALPHABET_SIZE = 26;
const MIN_SHIFT = 1;
const MAX_SHIFT = 25;
const EXAMPLE_TEXT = "Meet me at the library at 5 PM, and bring the notes!";

/* ---------- Core cipher logic ---------- */

// Shift every letter by `shift` places. Negative shifts move backwards (used for decryption).
function caesarCipher(text, shift) {
  // Normalise so any integer (even negative or > 26) becomes a value from 0 to 25.
  const normalizedShift = ((shift % ALPHABET_SIZE) + ALPHABET_SIZE) % ALPHABET_SIZE;
  let result = "";
  for (const character of text) {
    const code = character.charCodeAt(0);
    if (code >= 65 && code <= 90) {            // uppercase A-Z
      result += String.fromCharCode(((code - 65 + normalizedShift) % ALPHABET_SIZE) + 65);
    } else if (code >= 97 && code <= 122) {    // lowercase a-z
      result += String.fromCharCode(((code - 97 + normalizedShift) % ALPHABET_SIZE) + 97);
    } else {
      result += character;                     // digits, spaces, punctuation, line breaks: unchanged
    }
  }
  return result;
}

function encryptText(plaintext, shift) { return caesarCipher(plaintext, shift); }
// Decrypting is just encrypting with the opposite shift.
function decryptText(ciphertext, shift) { return caesarCipher(ciphertext, -shift); }

// Returns an error message, or "" if the shift is a whole number from 1 to 25.
function validateShift(shift) {
  if (!Number.isInteger(shift) || shift < MIN_SHIFT || shift > MAX_SHIFT) {
    return `Shift must be a whole number from ${MIN_SHIFT} to ${MAX_SHIFT}.`;
  }
  return "";
}

/* ---------- Interface ---------- */

if (typeof document !== "undefined") {
  const $ = id => document.getElementById(id);
  const plaintextBox = $("plaintext"), shiftInput = $("shift"), statusLine = $("status");
  const cipherBox = $("ciphertext"), decryptedBox = $("decrypted");
  const copyCipherBtn = $("copy-cipher-btn"), copyDecryptedBtn = $("copy-decrypted-btn");
  let currentCiphertext = "";   // last generated ciphertext
  let ciphertextShift = null;   // shift that was used to create it

  function setStatus(message, type) {
    statusLine.textContent = message;
    statusLine.className = "status " + (type || "");
  }

  // Result cards show a state badge ("Waiting" / success label) and a green border when done.
  function setCardState(box, tagId, done, label) {
    const stateBadge = $(tagId.replace("-shift", "-state"));
    stateBadge.textContent = label;
    stateBadge.classList.toggle("ok", done);
    box.closest(".result-card").classList.toggle("done", done);
  }

  function showOutput(box, text, tagId, shift, copyBtn) {
    box.textContent = text;
    box.classList.remove("placeholder");
    $(tagId).textContent = "Shift: " + shift;
    setCardState(box, tagId, true, tagId === "encrypt-shift" ? "Encrypted" : "Decrypted");
    copyBtn.disabled = false;
  }

  function clearOutput(box, placeholder, tagId, copyBtn) {
    box.textContent = placeholder;
    box.classList.add("placeholder");
    $(tagId).textContent = "";
    setCardState(box, tagId, false, "Waiting");
    copyBtn.disabled = true;
  }

  // Reads and validates the shift field; returns the number, or null after showing an error.
  function readShift() {
    const shift = Number(shiftInput.value);
    const error = shiftInput.value.trim() === "" ? "Please enter a shift value." : validateShift(shift);
    shiftInput.classList.toggle("invalid", error !== "");
    if (error) { setStatus(error, "error"); return null; }
    return shift;
  }

  function clearDecrypted() {
    clearOutput(decryptedBox, "The recovered message will appear here after decryption.", "decrypt-shift", copyDecryptedBtn);
  }

  function handleEncrypt() {
    if (plaintextBox.value === "") { setStatus("Please enter a message to encrypt.", "error"); plaintextBox.focus(); return; }
    const shift = readShift();
    if (shift === null) return;
    currentCiphertext = encryptText(plaintextBox.value, shift);
    ciphertextShift = shift;
    showOutput(cipherBox, currentCiphertext, "encrypt-shift", shift, copyCipherBtn);
    clearDecrypted();
    setStatus("Text encrypted successfully.", "success");
  }

  function handleDecrypt() {
    if (currentCiphertext === "") { setStatus("Encrypt some text first, then decrypt it.", "error"); return; }
    const shift = readShift();
    if (shift === null) return;
    showOutput(decryptedBox, decryptText(currentCiphertext, shift), "decrypt-shift", shift, copyDecryptedBtn);
    setStatus(shift === ciphertextShift ? "Text decrypted successfully."
      : "Decrypted with shift " + shift + ", which differs from the encryption shift (" + ciphertextShift + "), so the result is garbled.",
      shift === ciphertextShift ? "success" : "error");
  }

  // Copy using the Clipboard API, with an older fallback and a message if both fail.
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const temp = document.createElement("textarea");
        temp.value = text; temp.setAttribute("readonly", "");
        temp.style.position = "absolute"; temp.style.left = "-9999px";
        document.body.appendChild(temp); temp.select();
        const worked = document.execCommand("copy");
        document.body.removeChild(temp);
        if (!worked) throw new Error("copy failed");
      }
      setStatus("Copied to clipboard.", "success");
    } catch (err) {
      setStatus("Copy is not available here. Select the text and press Ctrl+C instead.", "error");
    }
  }

  function resetAll() {
    plaintextBox.value = ""; shiftInput.value = 3; $("shift-range").value = 3; shiftInput.classList.remove("invalid");
    currentCiphertext = ""; ciphertextShift = null;
    clearOutput(cipherBox, "Your ciphertext will appear here after encryption.", "encrypt-shift", copyCipherBtn);
    clearDecrypted();
    updateCounter(); setStatus("");
  }

  function updateCounter() {
    const length = plaintextBox.value.length;
    $("char-count").textContent = length + (length === 1 ? " character" : " characters");
  }

  plaintextBox.addEventListener("input", updateCounter);
  $("encrypt-btn").addEventListener("click", handleEncrypt);
  $("decrypt-btn").addEventListener("click", handleDecrypt);
  $("reset-btn").addEventListener("click", resetAll);
  $("clear-btn").addEventListener("click", () => { plaintextBox.value = ""; updateCounter(); setStatus(""); plaintextBox.focus(); });
  $("example-btn").addEventListener("click", () => { plaintextBox.value = EXAMPLE_TEXT; updateCounter(); setStatus("Example inserted. Now click Encrypt Text.", "success"); });
  copyCipherBtn.addEventListener("click", () => copyText(currentCiphertext));
  copyDecryptedBtn.addEventListener("click", () => copyText(decryptedBox.textContent));

  // "Try another shift": changing the key re-encrypts the existing text automatically.
  // Slider and number box stay in sync.
  $("shift-range").addEventListener("input", () => { shiftInput.value = $("shift-range").value; shiftInput.dispatchEvent(new Event("input")); });
  shiftInput.addEventListener("input", () => {
    shiftInput.classList.remove("invalid");
    if (validateShift(Number(shiftInput.value)) === "" && shiftInput.value !== "") $("shift-range").value = shiftInput.value;
    if (currentCiphertext !== "" && plaintextBox.value !== "" && validateShift(Number(shiftInput.value)) === "") handleEncrypt();
  });
}

if (typeof module !== "undefined") module.exports = { caesarCipher, encryptText, decryptText, validateShift };
