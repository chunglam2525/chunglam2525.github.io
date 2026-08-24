import { compactDecrypt, decodeProtectedHeader } from "./lib/jose.esm.js";

const secretInput = document.getElementById("secret");
const tokenInput = document.getElementById("token");
const decodeButton = document.getElementById("decode");
const copyButton = document.getElementById("copy");
const errorEl = document.getElementById("error");
const outputEl = document.getElementById("output");
const metaEl = document.getElementById("meta");

let lastPayloadText = "";

function showError(message) {
  errorEl.hidden = false;
  errorEl.textContent = message;
}

function clearError() {
  errorEl.hidden = true;
  errorEl.textContent = "";
}

function normalizeToken(raw) {
  let token = raw.trim().replace(/^["']|["']$/g, "");
  const cookie = token.match(
    /(?:^|[;\s])(?:__Secure-)?next-auth\.session-token=([^;]+)/i
  );
  if (cookie) {
    token = decodeURIComponent(cookie[1]);
  }
  return token.trim();
}

async function deriveKey(secret, algorithm) {
  const info =
    algorithm === "dir"
      ? "NextAuth.js Generated Encryption Key"
      : "NextAuth.js Generated A256GCMKW CEK";

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(),
      info: new TextEncoder().encode(info),
    },
    await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      "HKDF",
      false,
      ["deriveBits"]
    ),
    256
  );

  // jose picks AES-GCM vs AES-GCM-KW from the JWE header
  return new Uint8Array(bits);
}

async function decodeNextAuthJWE(token, secret) {
  const header = decodeProtectedHeader(token);
  const algorithm = header.alg;

  if (algorithm !== "dir" && algorithm !== "A256GCMKW") {
    throw new Error(`Unsupported algorithm: ${algorithm || "unknown"}`);
  }

  const key = await deriveKey(secret, algorithm);
  const { plaintext, protectedHeader } = await compactDecrypt(token, key);
  const text = new TextDecoder().decode(plaintext);

  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    payload = { raw: text };
  }

  return { header: protectedHeader, payload };
}

async function handleDecode() {
  const secret = secretInput.value.trim();
  const token = normalizeToken(tokenInput.value);

  if (!secret || !token) {
    showError("Please provide both secret and token.");
    return;
  }

  decodeButton.disabled = true;
  decodeButton.textContent = "Decoding...";
  clearError();
  copyButton.hidden = true;
  metaEl.hidden = true;
  outputEl.classList.add("empty");
  outputEl.textContent = "Decoding…";
  lastPayloadText = "";

  try {
    const { header, payload } = await decodeNextAuthJWE(token, secret);
    lastPayloadText = JSON.stringify(payload, null, 2);
    outputEl.classList.remove("empty");
    outputEl.textContent = lastPayloadText;
    metaEl.hidden = false;
    metaEl.textContent = `alg: ${header.alg || "?"} · enc: ${header.enc || "?"}`;
    copyButton.hidden = false;
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown decoding error";
    showError(`Decoding failed: ${message}`);
    outputEl.classList.add("empty");
    outputEl.textContent = "Decoded JSON will appear here.";
  } finally {
    decodeButton.disabled = false;
    decodeButton.textContent = "Decode token";
  }
}

async function handleCopy() {
  if (!lastPayloadText) return;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(lastPayloadText);
    } else {
      throw new Error("clipboard API unavailable");
    }
    copyButton.textContent = "Copied";
    setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1200);
  } catch {
    const area = document.createElement("textarea");
    area.value = lastPayloadText;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    if (ok) {
      copyButton.textContent = "Copied";
      setTimeout(() => {
        copyButton.textContent = "Copy";
      }, 1200);
    } else {
      showError("Could not copy to clipboard.");
    }
  }
}

decodeButton.addEventListener("click", handleDecode);
copyButton.addEventListener("click", handleCopy);

document.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
    event.preventDefault();
    handleDecode();
  }
});
