"""
crypto.py — Couche de stockage uniquement.
Le chiffrement/déchiffrement se fait côté client (JavaScript).
Le serveur ne voit JAMAIS le contenu en clair.
"""
import os
import sqlite3
import hashlib
import base64
from datetime import datetime

DB = "cloud.db"
STORAGE_DIR = "storage"


def init():
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username        TEXT PRIMARY KEY,
            password_hash   TEXT NOT NULL,
            quota_bytes     INTEGER NOT NULL,
            used_bytes      INTEGER NOT NULL,
            public_key      TEXT NOT NULL,       -- base64 SPKI (généré dans le navigateur)
            private_key_enc TEXT NOT NULL        -- base64 clé privée chiffrée (par le navigateur)
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS files(
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            owner        TEXT NOT NULL,
            filename     TEXT NOT NULL,
            size_plain   INTEGER NOT NULL,
            size_stored  INTEGER NOT NULL,
            created_at   TEXT NOT NULL,
            enc_aes_key  TEXT NOT NULL,   -- base64 (chiffré par RSA côté client)
            iv           TEXT NOT NULL,   -- base64
            tag          TEXT NOT NULL,   -- base64
            path         TEXT NOT NULL,
            FOREIGN KEY(owner) REFERENCES users(username)
        )""")
        con.commit()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def register(username, password, quota_mb, pub_key_b64, priv_key_enc_b64):
    """Crée un utilisateur avec les clés générées côté client."""
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cur.fetchone():
            raise ValueError("Utilisateur existe déjà.")
        cur.execute("""
        INSERT INTO users(username,password_hash,quota_bytes,used_bytes,public_key,private_key_enc)
        VALUES(?,?,?,?,?,?)""",
            (username, sha256(password), quota_mb * 1024 * 1024, 0,
             pub_key_b64, priv_key_enc_b64))
        con.commit()
    os.makedirs(os.path.join(STORAGE_DIR, username), exist_ok=True)


def login(username, password) -> bool:
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        return bool(row and row[0] == sha256(password))


def get_private_key_enc(username) -> str:
    """Retourne la clé privée chiffrée (base64) pour le client."""
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT private_key_enc FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        return row[0] if row else None


def get_public_key(username) -> str:
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT public_key FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        return row[0] if row else None


def get_quota_info(username):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT quota_bytes,used_bytes FROM users WHERE username=?", (username,))
        return cur.fetchone()


def update_used(username, delta):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("UPDATE users SET used_bytes=used_bytes+? WHERE username=?",
                    (delta, username))
        con.commit()


def store_file(username, filename, size_plain,
               enc_aes_key_b64, iv_b64, tag_b64, encrypted_bytes):
    """Stocke un fichier déjà chiffré côté client."""
    quota, used = get_quota_info(username)
    if used + size_plain > quota:
        raise ValueError(f"Quota dépassé : utilisé={used}B, quota={quota}B, fichier={size_plain}B")

    user_dir = os.path.join(STORAGE_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    stored_name = f"{int(datetime.utcnow().timestamp())}_{filename}.bin"
    path = os.path.join(user_dir, stored_name)

    with open(path, "wb") as f:
        f.write(encrypted_bytes)

    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("""
        INSERT INTO files(owner,filename,size_plain,size_stored,created_at,enc_aes_key,iv,tag,path)
        VALUES(?,?,?,?,?,?,?,?,?)""",
            (username, filename, size_plain, os.path.getsize(path),
             datetime.utcnow().isoformat(),
             enc_aes_key_b64, iv_b64, tag_b64, path))
        con.commit()

    update_used(username, size_plain)


def list_files(username):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("""SELECT id,filename,size_plain,created_at
                       FROM files WHERE owner=? ORDER BY id DESC""", (username,))
        return cur.fetchall()


def get_file_data(username, file_id) -> dict:
    """Retourne les données chiffrées + clés pour déchiffrement côté client."""
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("""SELECT filename,enc_aes_key,iv,tag,path
                       FROM files WHERE id=? AND owner=?""", (file_id, username))
        row = cur.fetchone()
    if not row:
        raise ValueError("Fichier non trouvé ou accès refusé.")
    filename, enc_aes_key, iv, tag, path = row
    with open(path, "rb") as f:
        content = f.read()
    return {
        "filename":    filename,
        "enc_aes_key": enc_aes_key,
        "iv":          iv,
        "tag":         tag,
        "ciphertext":  base64.b64encode(content).decode()
    }


def get_file_meta(username, file_id) -> dict:
    """Retourne uniquement les métadonnées d'un fichier (pour la page Détails)."""
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("""SELECT id,filename,size_plain,size_stored,created_at,
                       enc_aes_key,iv,tag,path
                       FROM files WHERE id=? AND owner=?""", (file_id, username))
        row = cur.fetchone()
    if not row:
        raise ValueError("Fichier non trouvé.")
    enc_preview = ""
    try:
        with open(row[8], "rb") as f:
            enc_preview = " ".join(f"{b:02x}" for b in f.read(80))
    except Exception:
        enc_preview = "(fichier non trouvé)"
    return {
        "id":                row[0],
        "filename":          row[1],
        "size_plain":        row[2],
        "size_stored":       row[3],
        "created_at":        row[4][:19].replace("T", " "),
        "enc_aes_key":       row[5],
        "enc_aes_key_len":   len(base64.b64decode(row[5])),
        "iv":                row[6],
        "iv_len":            len(base64.b64decode(row[6])),
        "tag":               row[7],
        "tag_len":           len(base64.b64decode(row[7])),
        "stored_path":       row[8],
        "encrypted_preview": enc_preview,
    }


def delete_file(username, file_id):
    with sqlite3.connect(DB) as con:
        cur = con.cursor()
        cur.execute("SELECT path,size_plain FROM files WHERE id=? AND owner=?",
                    (file_id, username))
        row = cur.fetchone()
        if not row:
            raise ValueError("Fichier non trouvé.")
        path, size_plain = row
        if os.path.exists(path):
            os.remove(path)
        cur.execute("DELETE FROM files WHERE id=? AND owner=?", (file_id, username))
        con.commit()
    update_used(username, -size_plain)
