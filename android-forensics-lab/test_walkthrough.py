#!/usr/bin/env python3
"""
Automated End-to-End Student Walkthrough Verification Test
Validates that a student following the README.md steps from Phase 1 through Phase 6
can extract every breadcrumb, recover every stage flag, and decrypt crown_jewels.enc
to obtain the Final Master Flag.
"""

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import xml.etree.ElementTree as ET
import zipfile

# Add scripts/ to path so we can invoke generate_artifacts directly
LAB_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(LAB_DIR, "scripts")


def run_student_walkthrough_test():
    print("=" * 78)
    print("  RUNNING END-TO-END STUDENT WALKTHROUGH VERIFICATION TEST")
    print("=" * 78)

    temp_dir = tempfile.mkdtemp(prefix="android_forensics_test_")
    try:
        # 0. Generate all lab artifacts using scripts/generate_artifacts.py
        gen_script = os.path.join(SCRIPTS_DIR, "generate_artifacts.py")
        subprocess.run([sys.executable, gen_script, temp_dir], check=True)

        # =====================================================================
        # PHASE 1: Initial Access (SMS, Contacts/Calls, Chrome History)
        # =====================================================================
        print("\n[Phase 1] Testing SMS, Contacts/Calls, and Chrome History SQLite Databases...")

        # 1.1 Check Contacts & Calls
        contacts_db = os.path.join(temp_dir, "contacts2_forensic.db")
        conn = sqlite3.connect(contacts_db)
        contacts = conn.execute("SELECT display_name, phone_number, notes FROM contacts;").fetchall()
        calls = conn.execute("SELECT number, duration, cached_name FROM calls;").fetchall()
        conn.close()
        assert any("VIPER_OPS" in c[0] and "com.shadowvault.dropapp" in c[2] for c in contacts), "Missing VIPER_OPS contact clue!"
        assert len(calls) == 3, "Expected 3 call log entries!"
        print("  [+] Contacts & Call Logs verified: Found handler 'VIPER_OPS' (+15550192834) & package 'com.shadowvault.dropapp'")

        # 1.2 Check Chrome History
        chrome_db = os.path.join(temp_dir, "Chrome_History.db")
        conn = sqlite3.connect(chrome_db)
        downloads = conn.execute("SELECT target_path, tab_url FROM downloads;").fetchall()
        conn.close()
        assert downloads[0][0] == "/sdcard/Download/ShadowDrop_v1.4.apk", "Missing APK download path in Chrome_History.db!"
        print(f"  [+] Chrome Download History verified: {downloads[0][1]} -> {downloads[0][0]}")

        # 1.3 Check SMS Database (Active rows = 5, Deleted row 6 recoverable via deleted_msg_cache & raw bytes)
        sms_db = os.path.join(temp_dir, "mmssms_forensic.db")
        conn = sqlite3.connect(sms_db)
        active_sms = conn.execute("SELECT _id, address, body FROM sms;").fetchall()
        deleted_sms = conn.execute("SELECT orig_sms_id, sender, recovered_body FROM deleted_msg_cache;").fetchall()
        conn.close()
        assert len(active_sms) == 5, "Expected 5 active SMS messages after attacker deleted row 6!"
        assert "FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}" in deleted_sms[0][2], "Stage 1 Flag missing from deleted_msg_cache!"

        with open(sms_db, "rb") as f:
            raw_db_bytes = f.read()
        assert b"FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}" in raw_db_bytes, "Stage 1 Flag missing from raw SQLite page bytes!"
        print("  [+] Deleted SMS recovery verified: FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}")

        # =====================================================================
        # PHASE 2: Execution & Malicious APK Reverse Engineering
        # =====================================================================
        print("\n[Phase 2] Testing Sideloaded APK Decompilation, SharedPrefs & Stage-2 Dropper...")

        apk_path = os.path.join(temp_dir, "ShadowDrop_v1.4.apk")
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            assert "AndroidManifest.xml" in names
            assert "assets/c2_config.json" in names
            assert "classes.dex" in names
            c2_cfg = json.loads(zf.read("assets/c2_config.json").decode("utf-8"))
            dex_bytes = zf.read("classes.dex")

        assert c2_cfg["stage2_flag"] == "FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}"
        assert b"FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}" in dex_bytes
        print("  [+] ShadowDrop_v1.4.apk verified: Found C2 config & DEX strings -> FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}")

        # Parse auth_prefs.xml like a student would
        prefs_path = os.path.join(temp_dir, "auth_prefs.xml")
        tree = ET.parse(prefs_path)
        root = tree.getroot()
        prefs_map = {elem.attrib["name"]: (elem.text or elem.attrib.get("value")) for elem in root}

        b64_token = prefs_map["auth_bearer_b64"]
        decoded_token = base64.b64decode(b64_token).decode("utf-8")
        extracted_aes_key = prefs_map["staging_archive_key"]

        assert "FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}" in decoded_token
        assert extracted_aes_key == "ViperExfil2026!Key"
        print(f"  [+] SharedPreferences auth_prefs.xml verified: Decoded token & extracted AES vault key '{extracted_aes_key}'")

        # =====================================================================
        # PHASE 3: Privilege Escalation & Defense Evasion (adb root)
        # =====================================================================
        print("\n[Phase 3] Testing Defense Evasion Artifacts (/system/etc/hosts, dropper_stage2.sh)...")

        dropper_text = open(os.path.join(temp_dir, "dropper_stage2.sh"), encoding="utf-8").read()
        hosts_text = open(os.path.join(temp_dir, "hosts.poisoned"), encoding="utf-8").read()

        assert "package_verifier_enable 0" in dropper_text
        assert "FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}" in dropper_text
        assert "198.51.100.77   c2.shadowvault-ops.internal" in hosts_text
        assert "FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}" in hosts_text
        print("  [+] Defense Evasion verified: Play Protect disabled & /system/etc/hosts sinkholed -> FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}")

        # =====================================================================
        # PHASE 4: Root Persistence & Masquerading Daemon
        # =====================================================================
        print("\n[Phase 4] Testing Root Persistence (shadowd.rc, 99-shadow-persist.sh, kworker_netd, cron, SSH)...")

        for fname in ["shadowd.rc", "99-shadow-persist.sh", "kworker_netd", "root_cron", "authorized_keys"]:
            content = open(os.path.join(temp_dir, fname), encoding="utf-8").read()
            assert "FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}" in content, f"Missing Stage 4 flag in {fname}"

        print("  [+] Persistence mechanisms verified across Init RC, Magisk hook, kworker_netd, Cron & SSH -> FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}")

        # =====================================================================
        # PHASE 5: Collection & Reconnaissance (EXIF Photo, Wi-Fi, .sh_history)
        # =====================================================================
        print("\n[Phase 5] Testing Geotagged Photo EXIF, Wi-Fi Config Backup & Root Shell History...")

        img_bytes = open(os.path.join(temp_dir, "IMG_20261018_231405.jpg"), "rb").read()
        wifi_text = open(os.path.join(temp_dir, "WifiConfigStore.xml.bak"), encoding="utf-8").read()
        history_text = open(os.path.join(temp_dir, ".sh_history"), encoding="utf-8").read()

        assert b"FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}" in img_bytes, "Missing Stage 5 Flag in JPEG EXIF!"
        assert "FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}" in wifi_text, "Missing Stage 5 Flag in WifiConfigStore.xml.bak!"
        assert "openssl enc -aes-256-cbc -pbkdf2" in history_text, "Missing OpenSSL encryption clue in .sh_history!"
        print("  [+] EXIF Metadata, Wi-Fi dump & .sh_history verified -> FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}")

        # =====================================================================
        # PHASE 6: Exfiltration Staging & Decrypting crown_jewels.enc
        # =====================================================================
        print("\n[Phase 6] Testing Exfiltration Tarball & AES-256-CBC Decryption of crown_jewels.enc...")

        tar_path = os.path.join(temp_dir, ".exfil_staging.tar.gz")
        with tarfile.open(tar_path, "r:gz") as tf:
            members = tf.getnames()
            assert "exfil_manifest.txt" in members
            assert "wire_transfer_approvals_Q4.csv" in members
            manifest_txt = tf.extractfile("exfil_manifest.txt").read().decode("utf-8")
            assert "openssl enc -d -aes-256-cbc -pbkdf2" in manifest_txt

        enc_path = os.path.join(temp_dir, "crown_jewels.enc")
        dec_path = os.path.join(temp_dir, "crown_jewels_decrypted.txt")

        # Try decrypting with OpenSSL CLI (exact command from README.md)
        openssl_bin = shutil.which("openssl") or (
            r"C:\Program Files\Git\usr\bin\openssl.exe"
            if os.path.exists(r"C:\Program Files\Git\usr\bin\openssl.exe")
            else None
        )
        decrypted_text = None
        if openssl_bin:
            subprocess.run(
                [
                    openssl_bin,
                    "enc",
                    "-d",
                    "-aes-256-cbc",
                    "-pbkdf2",
                    "-in",
                    enc_path,
                    "-out",
                    dec_path,
                    "-pass",
                    f"pass:{extracted_aes_key}",
                ],
                check=True,
            )
            decrypted_text = open(dec_path, encoding="utf-8").read()
            print(f"  [+] Decrypted crown_jewels.enc using OpenSSL CLI ({openssl_bin})")
        else:
            # Pure-Python PBKDF2 AES-256-CBC verification
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.primitives import padding

            enc_bytes = open(enc_path, "rb").read()
            assert enc_bytes[:8] == b"Salted__"
            salt = enc_bytes[8:16]
            ct = enc_bytes[16:]
            dk = hashlib.pbkdf2_hmac("sha256", extracted_aes_key.encode("utf-8"), salt, 10000, 48)
            key, iv = dk[:32], dk[32:48]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ct) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_text = (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
            print("  [+] Decrypted crown_jewels.enc using OpenSSL PBKDF2-AES-256-CBC format")

        assert "FLAG{m4st3r_f0r3ns1c_1nv3st1g4t0r_c0mpl3t3_ch41n}" in decrypted_text
        print("  [+] FINAL MASTER FLAG VERIFIED: FLAG{m4st3r_f0r3ns1c_1nv3st1g4t0r_c0mpl3t3_ch41n}")

        # =====================================================================
        # SAFETY CHECK: Ensure Final Master Flag & AES Key are NOT leaked in README.md
        # =====================================================================
        readme_text = open(os.path.join(LAB_DIR, "README.md"), encoding="utf-8").read()
        assert "FLAG{m4st3r_f0r3ns1c_1nv3st1g4t0r_c0mpl3t3_ch41n}" not in readme_text, "Final Master Flag leaked in README.md!"
        assert "ViperExfil2026!Key" not in readme_text, "Vault AES key leaked in README.md!"
        print("\n[Safety Check] Verified README.md does NOT leak the AES Key or Final Master Flag!")

        print("\n" + "=" * 78)
        print("  ALL 6 PHASES & STUDENT WALKTHROUGH STEPS PASSED 100%!")
        print("=" * 78)

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    run_student_walkthrough_test()
