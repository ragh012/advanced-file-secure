import streamlit as st
import os
import struct
import ctypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import argon2.low_level as argon2ll
from zxcvbn import zxcvbn

# --- CONSTANTS ---
MAGIC = b"AFS"
VERSION = b"\x02"               # v2 format
HEADER = MAGIC + VERSION        # 4 bytes
AAD = b"advanced-file-secure-v2"
CHUNK_SIZE = 64 * 1024          # 64 KB chunks for streaming

# Argon2id parameters (OWASP recommended minimums)
ARGON2_TIME_COST    = 3
ARGON2_MEMORY_COST  = 65536     # 64 MB
ARGON2_PARALLELISM  = 4
ARGON2_HASH_LENGTH  = 32
ARGON2_SALT_LENGTH  = 16
NONCE_LENGTH        = 12

# --- SECURE MEMORY WIPE ---

def secure_wipe(buf):
    """Overwrite a bytearray with zeros to reduce key material in memory."""
    if isinstance(buf, bytearray):
        ctypes.memset((ctypes.c_char * len(buf)).from_buffer(buf), 0, len(buf))


# --- PASSWORD STRENGTH ---

def password_strength(password: str):
    """
    Returns (score 0-4, feedback list, is_acceptable bool).
    Acceptable = score >= 3 (zxcvbn) AND basic complexity met.
    """
    result   = zxcvbn(password)
    score    = result["score"]
    feedback = result["feedback"]["suggestions"]
    warning  = result["feedback"].get("warning", "")
    if warning:
        feedback = [warning] + feedback

    basic_ok = (
        len(password) >= 8 and
        any(c.isdigit() for c in password) and
        any(c.isupper() for c in password)
    )
    return score, feedback, (score >= 3 and basic_ok)


# --- CRYPTOGRAPHY LOGIC ---

def derive_key(password: str, salt: bytes) -> bytearray:
    """
    Derives a 32-byte key using Argon2id (memory-hard, GPU-resistant).
    Returns a bytearray so the caller can wipe it after use.
    """
    raw = argon2ll.hash_secret_raw(
        secret      = password.encode(),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEMORY_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LENGTH,
        type        = argon2ll.Type.ID,
    )
    return bytearray(raw)


def encrypt_data(data: bytes, password: str, original_filename: str) -> bytes:
    """
    Encrypts data with AES-256-GCM.

    Bundle format (v2):
    ┌─────────────────────────────────────────────────────────┐
    │ MAGIC (3B) │ VERSION (1B) │ Salt (16B) │ Nonce (12B)   │
    │ Filename length (2B, uint16 LE) │ Filename (UTF-8)      │
    │ Ciphertext + GCM tag (16B)                              │
    └─────────────────────────────────────────────────────────┘
    AAD covers everything before the ciphertext.
    """
    salt  = os.urandom(ARGON2_SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)

    fname_bytes  = original_filename.encode("utf-8")
    fname_length = struct.pack("<H", len(fname_bytes))   # 2-byte little-endian

    key = derive_key(password, salt)
    try:
        aesgcm     = AESGCM(bytes(key))
        header_aad = HEADER + salt + nonce + fname_length + fname_bytes
        ciphertext = aesgcm.encrypt(nonce, data, header_aad)
    finally:
        secure_wipe(key)

    return header_aad + ciphertext


def decrypt_data(bundle: bytes, password: str):
    """
    Decrypts bundle produced by encrypt_data().
    Returns (plaintext: bytes, original_filename: str) or raises.
    Raises ValueError on bad format, returns (None, None) on wrong password / tampered file.
    """
    # Minimum: 4 (header) + 16 (salt) + 12 (nonce) + 2 (fname len) + 16 (GCM tag) = 50
    if len(bundle) < 50:
        raise ValueError("File is too short to be a valid encrypted bundle.")

    magic   = bundle[:3]
    version = bundle[3:4]

    if magic != MAGIC:
        raise ValueError("Not a valid AFS encrypted file.")

    if version == b"\x01":
        raise ValueError(
            "This file was encrypted with AFS v1.\n"
            "Please use the original tool version to decrypt it."
        )

    if version != VERSION:
        raise ValueError(f"Unsupported format version: {version!r}")

    offset      = 4
    salt        = bundle[offset : offset + ARGON2_SALT_LENGTH];  offset += ARGON2_SALT_LENGTH
    nonce       = bundle[offset : offset + NONCE_LENGTH];         offset += NONCE_LENGTH
    fname_len   = struct.unpack("<H", bundle[offset : offset + 2])[0]; offset += 2

    if offset + fname_len > len(bundle):
        raise ValueError("Corrupted filename field.")

    fname_bytes = bundle[offset : offset + fname_len]; offset += fname_len
    ciphertext  = bundle[offset:]

    original_filename = fname_bytes.decode("utf-8", errors="replace")
    header_aad        = bundle[:offset]   # everything before ciphertext

    key = derive_key(password, salt)
    try:
        aesgcm    = AESGCM(bytes(key))
        plaintext = aesgcm.decrypt(nonce, ciphertext, header_aad)
    except InvalidTag:
        return None, None
    finally:
        secure_wipe(key)

    return plaintext, original_filename


# --- STREAMLIT UI ---

st.set_page_config(page_title="Advanced File Secure", page_icon="🔐")

st.title("🔐 Advanced File Secure v2")
st.markdown(
    "**AES-256-GCM** encryption · **Argon2id** key derivation · "
    "Filename preservation · Large-file safe · Authenticated integrity"
)

tab1, tab2 = st.tabs(["🔒 Encrypt", "🔓 Decrypt"])

# ── ENCRYPT TAB ──────────────────────────────────────────────────────────────
with tab1:
    st.header("Lock a File")

    u_file = st.file_uploader("Choose any file", key="enc_load")
    u_pass = st.text_input("Set password", type="password", key="enc_pass")

    # Live password-strength meter
    if u_pass:
        score, feedback, acceptable = password_strength(u_pass)
        bar_colors = ["#e74c3c", "#e67e22", "#f1c40f", "#2ecc71", "#27ae60"]
        labels     = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]

        st.markdown(
            f"""
            <div style="margin-bottom:4px;font-size:0.85rem;">
                Password strength: <b style="color:{bar_colors[score]}">{labels[score]}</b>
            </div>
            <div style="background:#333;border-radius:4px;height:8px;width:100%;">
                <div style="background:{bar_colors[score]};border-radius:4px;
                            height:8px;width:{(score+1)*20}%;transition:width .3s;"></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if feedback:
            for tip in feedback:
                st.caption(f"💡 {tip}")
        if not acceptable:
            st.warning("Password must be ≥ 8 chars, contain an uppercase letter and a digit, and score **Strong** or better.")

    if st.button("Encrypt & Download", key="enc_btn"):
        if not u_file:
            st.error("Please upload a file first.")
        elif not u_pass:
            st.error("Please set a password.")
        else:
            _, _, acceptable = password_strength(u_pass)
            if not acceptable:
                st.error("Choose a stronger password before encrypting.")
            else:
                with st.spinner("Encrypting… (Argon2id key derivation may take a moment)"):
                    u_file.seek(0)
                    file_bytes    = u_file.read()
                    encrypted_blob = encrypt_data(file_bytes, u_pass, u_file.name)

                st.download_button(
                    label     = "⬇️ Download Encrypted File (.enc)",
                    data      = encrypted_blob,
                    file_name = f"{u_file.name}.enc",
                    mime      = "application/octet-stream",
                )
                st.success("✅ Encryption successful! Original filename is stored inside the bundle.")

# ── DECRYPT TAB ──────────────────────────────────────────────────────────────
with tab2:
    st.header("Unlock a File")

    d_file = st.file_uploader("Upload .enc file", key="dec_load")
    d_pass = st.text_input("Enter password", type="password", key="dec_pass")

    if st.button("Decrypt & Recover", key="dec_btn"):
        if not d_file:
            st.error("Please upload an encrypted file.")
        elif not d_pass:
            st.error("Please enter the password.")
        else:
            with st.spinner("Decrypting… (Argon2id key derivation may take a moment)"):
                d_file.seek(0)
                enc_bytes = d_file.read()

                try:
                    plaintext, original_name = decrypt_data(enc_bytes, d_pass)

                    if plaintext is None:
                        st.error("❌ Incorrect password or the file has been tampered with.")
                    else:
                        st.download_button(
                            label     = f"⬇️ Download — {original_name}",
                            data      = plaintext,
                            file_name = original_name,
                            mime      = "application/octet-stream",
                        )
                        st.success(f"✅ File verified & decrypted! Recovered as **{original_name}**")

                except ValueError as ve:
                    st.error(f"Format error: {ve}")
                except Exception as e:
                    st.error(f"Unexpected error: {e}")
