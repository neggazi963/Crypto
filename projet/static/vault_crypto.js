/**
 * VaultCrypto — Chiffrement E2E côté client
 * Utilise l'API Web Crypto (standard navigateur)
 * RSA-OAEP 2048 bits + AES-256-GCM
 *
 * Le serveur ne reçoit JAMAIS de données en clair.
 */

const VaultCrypto = (() => {

  // ── Utilitaires base64 ──────────────────────────────────────────

  /** ArrayBuffer → base64 */
  const toB64 = (buf) => {
    const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  };

  /** base64 → Uint8Array */
  const fromB64 = (b64) => {
    const binary = atob(b64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  };

  /** Uint8Array → "xx xx xx ..." (pour affichage hex) */
  const toHex = (buf) =>
    Array.from(new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer))
      .map(b => b.toString(16).padStart(2, "0"))
      .join(" ");

  // ── Génération des clés RSA ──────────────────────────────────────

  /**
   * Génère une paire de clés RSA-OAEP 2048 bits dans le navigateur.
   * Ces clés ne quittent JAMAIS le navigateur en clair.
   */
  async function generateKeyPair() {
    return crypto.subtle.generateKey(
      {
        name:           "RSA-OAEP",
        modulusLength:  2048,
        publicExponent: new Uint8Array([1, 0, 1]),  // 65537
        hash:           "SHA-256",
      },
      true,              // exportable
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Exporte la clé publique en base64 (format SPKI).
   * C'est cette valeur qui est envoyée au serveur.
   */
  async function exportPublicKeyB64(publicKey) {
    const buf = await crypto.subtle.exportKey("spki", publicKey);
    return toB64(buf);
  }

  /**
   * Chiffre la clé privée avec le mot de passe de l'utilisateur.
   * Algorithme : PBKDF2 (100 000 itérations) → AES-256-GCM
   * Format résultat : salt(16) + iv(12) + ciphertext  encodé en base64
   */
  async function encryptPrivateKey(privateKey, password) {
    // 1. Exporter la clé privée en PKCS8
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);

    // 2. Dériver une clé AES depuis le mot de passe
    const salt   = crypto.getRandomValues(new Uint8Array(16));
    const iv     = crypto.getRandomValues(new Uint8Array(12));
    const pwdKey = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      pwdKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );

    // 3. Chiffrer la clé privée
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, pkcs8);

    // 4. Concaténer salt + iv + ciphertext
    const combined = new Uint8Array(16 + 12 + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, 16);
    combined.set(new Uint8Array(encrypted), 28);
    return toB64(combined.buffer);
  }

  /**
   * Déchiffre la clé privée avec le mot de passe.
   * Retourne un CryptoKey prêt à déchiffrer.
   */
  async function decryptPrivateKey(encB64, password) {
    const combined = fromB64(encB64);
    const salt      = combined.slice(0, 16);
    const iv        = combined.slice(16, 28);
    const encrypted = combined.slice(28);

    const pwdKey = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]
    );
    const aesKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
      pwdKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    const pkcs8 = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, encrypted);
    return crypto.subtle.importKey(
      "pkcs8", pkcs8,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["decrypt"]
    );
  }

  /**
   * Importe une clé publique depuis base64 SPKI.
   */
  async function importPublicKey(b64) {
    return crypto.subtle.importKey(
      "spki", fromB64(b64),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["encrypt"]
    );
  }

  // ── Chiffrement de fichiers ──────────────────────────────────────

  /**
   * Chiffre un fichier entièrement dans le navigateur.
   *
   * Étape 1 : Génère une clé AES-256 aléatoire
   * Étape 2 : Chiffre le fichier avec AES-256-GCM
   * Étape 3 : Chiffre la clé AES avec la clé publique RSA
   *
   * @param {ArrayBuffer} fileBuffer  — contenu du fichier
   * @param {CryptoKey}   publicKey   — clé publique RSA de l'utilisateur
   * @returns {Object} { encryptedBlob, enc_aes_key, iv, tag } tous en base64
   */
  async function encryptFile(fileBuffer, publicKey) {
    // 1. Clé AES-256 aléatoire
    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // 2. Chiffrement AES-GCM (le tag GCM est ajouté à la fin automatiquement)
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      aesKey,
      fileBuffer
    );

    // 3. Séparer ciphertext et tag (les 16 derniers octets)
    const encBytes   = new Uint8Array(encrypted);
    const ciphertext = encBytes.slice(0, -16);
    const tag        = encBytes.slice(-16);

    // 4. Chiffrer la clé AES avec RSA-OAEP
    const rawAES    = await crypto.subtle.exportKey("raw", aesKey);
    const encAESKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, rawAES);

    // 5. Construire le Blob chiffré à envoyer au serveur
    const encryptedBlob = new Blob([ciphertext], { type: "application/octet-stream" });

    return {
      encryptedBlob,
      enc_aes_key: toB64(encAESKey),
      iv:          toB64(iv.buffer),
      tag:         toB64(tag.buffer),
    };
  }

  /**
   * Déchiffre un fichier entièrement dans le navigateur.
   *
   * Étape 1 : Déchiffre la clé AES avec la clé privée RSA
   * Étape 2 : Déchiffre le fichier avec AES-256-GCM + vérification du tag
   *
   * @returns {ArrayBuffer} contenu déchiffré
   */
  async function decryptFile(ciphertextB64, encAESKeyB64, ivB64, tagB64, privateKey) {
    // 1. Déchiffrer la clé AES avec RSA
    const rawAES = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      fromB64(encAESKeyB64)
    );

    // 2. Importer la clé AES
    const aesKey = await crypto.subtle.importKey(
      "raw", rawAES, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );

    // 3. Recombiner ciphertext + tag pour Web Crypto
    const ciphertext = fromB64(ciphertextB64);
    const tag        = fromB64(tagB64);
    const combined   = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    // 4. Déchiffrer + vérifier intégrité (tag GCM)
    return crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromB64(ivB64), tagLength: 128 },
      aesKey,
      combined.buffer
    );
  }

  // ── Interface publique ───────────────────────────────────────────
  return {
    toB64, fromB64, toHex,
    generateKeyPair,
    exportPublicKeyB64,
    encryptPrivateKey,
    decryptPrivateKey,
    importPublicKey,
    encryptFile,
    decryptFile,
  };
})();


// ═══════════════════════════════════════════════════════════════════
//  Session en mémoire — clé privée déchiffrée
//  Jamais stockée sur le serveur, jamais dans localStorage
// ═══════════════════════════════════════════════════════════════════
window._vault = {
  privateKey: null,   // CryptoKey RSA (en mémoire seulement)
  username:   null,
};
