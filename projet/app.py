import os
import base64
from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify)
import crypto

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "vaultcloud-e2e-dev-key")
crypto.init()


def logged_in():
    return "username" in session


def fmt_size(n):
    if n < 1024:       return f"{n} B"
    elif n < 1024**2:  return f"{n/1024:.1f} KB"
    elif n < 1024**3:  return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.1f} GB"


# ─── Pages HTML ──────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if logged_in() else url_for("login"))


@app.route("/login")
def login():
    if logged_in():
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/register")
def register():
    if logged_in():
        return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnecté.", "success")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not logged_in():
        return redirect(url_for("login"))
    u = session["username"]
    files = crypto.list_files(u)
    quota, used = crypto.get_quota_info(u)
    percent = round(used / quota * 100, 1) if quota > 0 else 0
    files_fmt = [
        {"id": f[0], "name": f[1],
         "size": fmt_size(f[2]), "date": f[3][:19].replace("T", " ")}
        for f in files
    ]
    return render_template("dashboard.html",
                           username=u,
                           files=files_fmt,
                           used=fmt_size(used),
                           quota=fmt_size(quota),
                           percent=percent)


@app.route("/details/<int:file_id>")
def details(file_id):
    if not logged_in():
        return redirect(url_for("login"))
    try:
        meta = crypto.get_file_meta(session["username"], file_id)
        pub_key = crypto.get_public_key(session["username"])
        meta["public_key"] = pub_key or ""
    except Exception as e:
        flash(str(e), "error")
        return redirect(url_for("dashboard"))
    return render_template("details.html", info=meta)


@app.route("/mes-cles")
def mes_cles():
    if not logged_in():
        return redirect(url_for("login"))
    pub_key = crypto.get_public_key(session["username"]) or ""
    priv_key_enc = crypto.get_private_key_enc(session["username"]) or ""
    return render_template("mes_cles.html",
                           pub_key_b64=pub_key,
                           priv_key_enc_b64=priv_key_enc)


# ─── API JSON ────────────────────────────────

@app.route("/api/register", methods=["POST"])
def api_register():
    """Le navigateur génère les clés RSA et les envoie ici."""
    data = request.get_json()
    username     = data.get("username", "").strip()
    password     = data.get("password", "")
    quota_mb     = int(data.get("quota", 5))
    pub_key_b64  = data.get("pub_key_b64", "")
    priv_key_enc = data.get("priv_key_enc", "")

    if not username or not password or not pub_key_b64 or not priv_key_enc:
        return jsonify({"error": "Champs manquants"}), 400
    try:
        crypto.register(username, password, quota_mb, pub_key_b64, priv_key_enc)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/login", methods=["POST"])
def api_login():
    """Vérifie le mot de passe et retourne la clé privée chiffrée."""
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not crypto.login(username, password):
        return jsonify({"error": "Identifiants incorrects"}), 401

    priv_key_enc = crypto.get_private_key_enc(username)
    session["username"] = username
    return jsonify({"success": True, "priv_key_enc": priv_key_enc})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Reçoit un fichier déjà chiffré côté client.
    Le serveur ne voit JAMAIS le contenu en clair.
    """
    if not logged_in():
        return jsonify({"error": "Non connecté"}), 401

    # Fichier chiffré (binaire)
    enc_file    = request.files.get("encrypted_file")
    enc_aes_key = request.form.get("enc_aes_key", "")
    iv          = request.form.get("iv", "")
    tag         = request.form.get("tag", "")
    filename    = request.form.get("filename", "fichier")
    size_plain  = int(request.form.get("size_plain", 0))

    if not enc_file:
        return jsonify({"error": "Fichier manquant"}), 400

    try:
        encrypted_bytes = enc_file.read()
        crypto.store_file(session["username"], filename, size_plain,
                          enc_aes_key, iv, tag, encrypted_bytes)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/download/<int:file_id>")
def api_download(file_id):
    """
    Retourne les données chiffrées pour déchiffrement côté client.
    Le serveur envoie du binaire illisible.
    """
    if not logged_in():
        return jsonify({"error": "Non connecté"}), 401
    try:
        data = crypto.get_file_data(session["username"], file_id)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/api/delete/<int:file_id>", methods=["POST"])
def api_delete(file_id):
    if not logged_in():
        return jsonify({"error": "Non connecté"}), 401
    try:
        crypto.delete_file(session["username"], file_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/my-public-key")
def api_my_public_key():
    """Retourne la clé publique de l'utilisateur connecté."""
    if not logged_in():
        return jsonify({"error": "Non connecté"}), 401
    pub = crypto.get_public_key(session["username"])
    return jsonify({"pub_key_b64": pub})


# ─────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, port=5000)
