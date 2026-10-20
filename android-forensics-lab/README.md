# Operation ShadowVault: Android Mobile Forensics & Incident Response Lab

An interactive mobile cybersecurity and digital forensics training environment simulating a full 6-stage Android device compromise: **Smishing Initial Access -> Sideloaded Dropper APK -> Root Privilege Escalation & Defense Evasion -> Boot & Daemon Persistence -> Geolocation & Credential Collection -> Encrypted Exfiltration Vault Recovery**.

---

## Scenario Briefing

A corporate Samsung Galaxy S10 (`SM-G973F`, Android 11) belonging to a SOC analyst was flagged by network monitoring after communicating with an unauthorized external IP (`198.51.100.77`). Shortly before the device was isolated, approximately 1.4 million USD in unauthorized wire transfers were initiated from the analyst's account.

As the lead Mobile Forensics Investigator, you have been provided with a **Kali Linux Forensics Workstation** connected over an isolated forensic network to the live **Android Target Device**. Your mission is to follow the threat actor's trail across the device, uncover how they achieved persistence, reconstruct the 6-stage attack timeline, and decrypt the staged exfiltration vault to capture the **Final Master Flag**.

---

## Student Quick Start & Setup Guide

### System Requirements
* **Docker**: [Docker Desktop](https://docs.docker.com/get-docker/) (Windows / macOS with WSL2 & nested virtualization enabled) or Docker Engine (Linux with `/dev/kvm`).
* **RAM & Storage**: Minimum **4 GB to 6 GB of available RAM** and **8 GB of free disk space** (for the Android 11 emulator and Kali XFCE desktop image).
* **Port Availability**:
  * `6080` — Android Target Web GUI (noVNC)
  * `6081` — Kali Forensics Desktop Web GUI (noVNC)
  * `2222` — Kali Forensics OpenSSH Server
  * `5555` — Android ADB over TCP

### Installation & Launch (Windows, macOS, Linux)

1. **Navigate to the Lab Directory**:
   ```bash
   cd android-forensics-lab
   ```

2. **Build and Launch the Environment**:
   ```bash
   docker compose up --build -d
   ```

3. **Wait for Evidence Seeding (~60–90 seconds)**:
   The Android emulator takes roughly 60–90 seconds to complete its boot sequence (`sys.boot_completed=1`). Once booted, the background seeder automatically connects via `adb root` and plants the 6-stage forensic trail. You can watch the progress live:
   ```bash
   docker compose logs -f kali-forensics
   ```
   Wait until you see:
   `[+] Complete 6-Stage Malicious Actor Trail & Persistence successfully planted on 172.28.0.10:5555!`

   > [!TIP]
   > **Offline Fallback Image (No-KVM Support)**: If your host laptop or VM does not support nested hardware virtualization (`/dev/kvm`), the seeder automatically generates a complete logical extraction archive at `/home/investigator/evidence/android_logical_extraction_fallback.tar.gz` inside the Kali workstation so you can still complete the entire investigation!

4. **Access Your Lab Machines**:
   * **Kali Forensics Desktop (Web GUI)**: [http://localhost:6081/vnc.html](http://localhost:6081/vnc.html)
     * **VNC Password**: `forensics`
   * **Kali Forensics Terminal (SSH)**:
     ```bash
     ssh investigator@localhost -p 2222
     ```
     * **SSH Password**: `forensics`
   * **Android Target Screen (Web GUI)**: [http://localhost:6080](http://localhost:6080)

---

## Architecture & Forensic Investigation Trail

```text
+---------------------------------------------------------------------------------------+
|                   KALI LINUX FORENSICS WORKSTATION (172.28.0.20)                      |
|   - Web Desktop: http://localhost:6081/vnc.html  |  SSH: localhost:2222               |
|   - Pre-installed: adb, jadx-gui, apktool, sqlite3, sqlitebrowser, exiftool, openssl  |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            | Isolated Forensics Bridge (172.28.0.0/16)
                                            | ADB over TCP (172.28.0.10:5555)
                                            v
+---------------------------------------------------------------------------------------+
|                    ANDROID 11.0 TARGET EMULATOR (172.28.0.10)                         |
|                                                                                       |
|  [Phase 1: Initial Access]                                                            |
|    - Inspect SMS, Contacts/Calls & Chrome History SQLite DBs                          |
|    - Recover deleted SMS row -> Uncover Stage 1 Flag & sideloaded APK path            |
|                                           |                                           |
|                                           v                                           |
|  [Phase 2: Execution & APK Reverse Engineering]                                       |
|    - Pull /sdcard/Download/ShadowDrop_v1.4.apk & decompile with JADX / apktool        |
|    - Inspect /data/data/com.shadowvault.dropapp/ (auth_prefs.xml & dropper_stage2.sh) |
|                                           |                                           |
|                                           v                                           |
|  [Phase 3: Privilege Escalation & Defense Evasion]                                    |
|    - Audit tampered Android Global Settings, System Properties, Logcat & /etc/hosts   |
|    - Discover disabled Play Protect & C2 DNS sinkholing -> Uncover Stage 3 Flag       |
|                                           |                                           |
|                                           v                                           |
|  [Phase 4: Multi-Layered Root Persistence]                                            |
|    - Hunt live masquerading root process (kworker_netd) & TCP port 31337 listener     |
|    - Inspect /system/etc/init/shadowd.rc, /data/adb/service.d/, Cron & SSH keys       |
|                                           |                                           |
|                                           v                                           |
|  [Phase 5: Collection & Geolocation Reconnaissance]                                   |
|    - Extract GPS coordinates & Stage 5 Flag from DCIM photo EXIF metadata             |
|    - Inspect dumped Wi-Fi config & attacker's root shell history (.sh_history)        |
|                                           |                                           |
|                                           v                                           |
|  [Phase 6: Exfiltration Vault Decryption -> FINAL MASTER FLAG]                        |
|    - Pull /data/local/tmp/.staging/crown_jewels.enc                                   |
|    - Decrypt AES-256-CBC vault using key from Phase 2 & OpenSSL command from Phase 5  |
+---------------------------------------------------------------------------------------+
```

---

## Guided Investigation Walkthrough

Open a terminal inside your **Kali Forensics Workstation** (either via the Web GUI at `http://localhost:6081/vnc.html` or via SSH at `ssh investigator@localhost -p 2222`) and ensure you are working inside your `/home/investigator/evidence` directory:

```bash
cd ~/evidence
mkdir -p stage1 stage2 stage3 stage4 stage5 stage6
```

### Connecting to the Target via ADB

1. Connect to the Android emulator over the forensic network and elevate your ADB session to `root` so you can acquire protected system and application directories:
   ```bash
   adb connect 172.28.0.10:5555
   adb root
   adb connect 172.28.0.10:5555
   ```
2. Verify device connectivity and basic hardware/OS properties:
   ```bash
   adb devices -l
   adb shell getprop ro.product.model
   adb shell getprop ro.build.version.release
   ```

---

### Phase 1: Initial Access — SMS, Call Logs & Browser Forensics

#### Investigative Goal
Determine how the threat actor initially contacted the victim, what file was delivered to the device, and whether the attacker attempted to cover their tracks by deleting messages.

#### Step-by-Step Procedure
1. **Acquire the Communications & Browser Databases**:
   Pull the SMS/MMS database, Contacts/Call Logs database, and Chrome Browser History database from the Android target into `~/evidence/stage1/`:
   ```bash
   adb pull /data/data/com.android.providers.telephony/databases/mmssms_forensic.db ~/evidence/stage1/
   adb pull /data/data/com.android.providers.contacts/databases/contacts2_forensic.db ~/evidence/stage1/
   adb pull /data/data/com.android.chrome/app_chrome/Default/History ~/evidence/stage1/Chrome_History.db
   ```

2. **Analyze Contacts and Call Logs**:
   Query `contacts2_forensic.db` using `sqlite3` (or open it graphically using **DB Browser for SQLite** on your Kali Desktop):
   ```bash
   sqlite3 -header -column ~/evidence/stage1/contacts2_forensic.db "SELECT * FROM contacts;"
   sqlite3 -header -column ~/evidence/stage1/contacts2_forensic.db "SELECT * FROM calls;"
   ```
   *Observation*: Notice the suspicious handler contact **`VIPER_OPS`** (`+15550192834`) and the notes referencing C2 IP `198.51.100.77` and package `com.shadowvault.dropapp`.

3. **Inspect Chrome Download History**:
   ```bash
   sqlite3 -header -column ~/evidence/stage1/Chrome_History.db "SELECT url, title FROM urls;"
   sqlite3 -header -column ~/evidence/stage1/Chrome_History.db "SELECT target_path, tab_url, total_bytes FROM downloads;"
   ```
   *Observation*: The user downloaded an Android package from `http://198.51.100.77:8080/update/ShadowDrop_v1.4.apk` to `/sdcard/Download/ShadowDrop_v1.4.apk`.

4. **Examine Active SMS Messages & Recover Deleted Evidence**:
   Query the active `sms` table in `mmssms_forensic.db`:
   ```bash
   sqlite3 -header -column ~/evidence/stage1/mmssms_forensic.db "SELECT _id, address, date, body FROM sms;"
   ```
   Notice that `_id` stops at `5`, or check if there are other tables or unvacuumed deleted data left behind when the attacker deleted a message (`PRAGMA secure_delete = OFF`):
   ```bash
   sqlite3 ~/evidence/stage1/mmssms_forensic.db ".tables"
   sqlite3 -header -column ~/evidence/stage1/mmssms_forensic.db "SELECT * FROM deleted_msg_cache;"
   strings ~/evidence/stage1/mmssms_forensic.db | grep -i "FLAG{"
   ```
   * **Stage 1 Flag**: `FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}`
   * **Next Breadcrumb**: The recovered SMS points you directly to `/sdcard/Download/ShadowDrop_v1.4.apk` and the application directory for `com.shadowvault.dropapp`.

---

### Phase 2: Execution — Malicious APK Reverse Engineering & App Data

#### Investigative Goal
Acquire and reverse-engineer the sideloaded `ShadowDrop_v1.4.apk` payload and inspect the private application data directory (`/data/data/com.shadowvault.dropapp/`) to see what the malware executed and what keys/tokens it stored.

#### Step-by-Step Procedure
1. **Pull the Sideloaded APK & Application Data**:
   ```bash
   adb pull /sdcard/Download/ShadowDrop_v1.4.apk ~/evidence/stage2/
   adb pull /data/data/com.shadowvault.dropapp/ ~/evidence/stage2/com.shadowvault.dropapp/
   ```

2. **Decompile and Inspect `ShadowDrop_v1.4.apk`**:
   You can open `ShadowDrop_v1.4.apk` inside **JADX-GUI** (`jadx-gui ~/evidence/stage2/ShadowDrop_v1.4.apk`) on the Kali desktop, or unpack it from the terminal:
   ```bash
   unzip -q ~/evidence/stage2/ShadowDrop_v1.4.apk -d ~/evidence/stage2/apk_unpacked
   ls -la ~/evidence/stage2/apk_unpacked
   ```
   Inspect the manifest, embedded C2 configuration, and Java/DEX code:
   ```bash
   cat ~/evidence/stage2/apk_unpacked/assets/c2_config.json
   cat ~/evidence/stage2/apk_unpacked/src/com/shadowvault/dropapp/BeaconService.java
   strings ~/evidence/stage2/apk_unpacked/classes.dex
   ```
   *Observation*: `BeaconService` executes a second-stage root script (`/data/data/com.shadowvault.dropapp/files/dropper_stage2.sh`) via `su -c` and references `/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml`.

3. **Analyze `auth_prefs.xml` & Decode the Session Token**:
   ```bash
   cat ~/evidence/stage2/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml
   ```
   * Decode the `auth_bearer_b64` Base64 string:
     ```bash
     echo "<BASE64_STRING_FROM_AUTH_PREFS>" | base64 -d ; echo
     ```
   * **Important**: Record the `staging_archive_key` value found in `auth_prefs.xml` — you will need this key in **Phase 6** to decrypt the final exfiltration vault!

4. **Analyze the Dropped Root Script (`dropper_stage2.sh`)**:
   ```bash
   cat ~/evidence/stage2/com.shadowvault.dropapp/files/dropper_stage2.sh
   ```
   * **Stage 2 Flag**: `FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}`
   * **Next Breadcrumb**: `dropper_stage2.sh` reveals how the attacker abused `adb root` to tamper with Android `settings`, `setprop` system properties, and `/system/etc/hosts`.

---

### Phase 3: Privilege Escalation & Defense Evasion (`adb root`)

#### Investigative Goal
Audit the live Android operating system configuration to identify how the threat actor weakened device security, sinkholed security updates, and left persistent configuration markers.

#### Step-by-Step Procedure
1. **Audit Android Global Settings**:
   Query the device's global settings for disabled security verifiers and attacker tokens:
   ```bash
   adb shell settings get global package_verifier_enable
   adb shell settings get global verifier_verify_adb_installs
   adb shell settings list global | grep -E "verifier|adb|shadow"
   ```
   *Observation*: `package_verifier_enable` and `verifier_verify_adb_installs` were set to `0` (disabling Google Play Protect checks), and a custom key `shadowvault_evasion_token` is present.

2. **Audit Persistent Android System Properties (`getprop`)**:
   ```bash
   adb shell getprop | grep shadow
   ```
   *Observation*: Notice `persist.sys.shadow.c2` (`198.51.100.77:8443`) and `persist.sys.shadow.init_rc` (`/system/etc/init/shadowd.rc`).

3. **Inspect the Poisoned `/system/etc/hosts` File**:
   ```bash
   adb shell cat /system/etc/hosts
   ```
   *Observation*: The attacker sinkholed `playprotect.googleapis.com` and `security-updates.samsung.com` to `127.0.0.1` and mapped `198.51.100.77` to `c2.shadowvault-ops.internal`.

4. **Check Android System Logs (`logcat`) for Rootkit Activity**:
   ```bash
   adb logcat -d | grep -i "ShadowDrop"
   ```
   * **Stage 3 Flag**: `FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}`
   * **Next Breadcrumb**: Both `getprop`, `/system/etc/hosts`, and `logcat` point to boot persistence scripts in `/system/etc/init/shadowd.rc` and `/data/adb/service.d/99-shadow-persist.sh`.

---

### Phase 4: Persistence — Init Scripts, Cron, SSH & Masquerading Root Daemon

#### Investigative Goal
Locate all persistence mechanisms planted by the threat actor and identify the live root process masquerading as a Linux kernel thread on the Android device.

#### Step-by-Step Procedure
1. **Inspect the Android Init RC & Magisk Boot Persistence Scripts**:
   ```bash
   adb shell cat /system/etc/init/shadowd.rc
   adb shell cat /data/adb/service.d/99-shadow-persist.sh
   ```
   *Observation*: Whenever `sys.boot_completed=1` fires, the system executes `/data/local/tmp/.sysd/kworker_netd`.

2. **Hunt for the Live Masquerading Process & Network Listener**:
   Attackers frequently name userland backdoors after Linux kernel worker threads (such as `kworker/...`) to blend into process listings. Search running processes on the Android target:
   ```bash
   adb shell ps -ef | grep kworker
   ```
   Check for active local network listeners or connect to local port `31337` referenced by the daemon:
   ```bash
   adb shell netstat -tulnp 2>/dev/null || adb shell ss -tulnp
   ```

3. **Acquire and Analyze the Hidden `/data/local/tmp/.sysd/` & `.ssh/` Directories**:
   ```bash
   adb shell ls -la /data/local/tmp/
   adb pull /data/local/tmp/.sysd/ ~/evidence/stage4/sysd/
   adb pull /data/local/tmp/.ssh/ ~/evidence/stage4/ssh/
   ```
   Inspect the daemon script, root crontab, and backdoor SSH key:
   ```bash
   cat ~/evidence/stage4/sysd/kworker_netd
   cat ~/evidence/stage4/sysd/root_cron
   cat ~/evidence/stage4/ssh/authorized_keys
   ```
   * **Stage 4 Flag**: `FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}`
   * **Next Breadcrumb**: The comments and beacon code inside `kworker_netd` reveal that the attacker collected reconnaissance artifacts in `/sdcard/DCIM/Camera/IMG_20261018_231405.jpg`, `/data/misc/wifi/WifiConfigStore.xml.bak`, and left shell history at `/data/local/tmp/.sh_history`.

---

### Phase 5: Collection & Reconnaissance — EXIF Geolocation, Wi-Fi Dump & Shell History

#### Investigative Goal
Determine the physical location of the attacker's dead drop via image metadata, inspect harvested Wi-Fi credentials, and reconstruct the attacker's interactive root commands.

#### Step-by-Step Procedure
1. **Pull the Reconnaissance Artifacts**:
   ```bash
   adb pull /sdcard/DCIM/Camera/IMG_20261018_231405.jpg ~/evidence/stage5/
   adb pull /data/misc/wifi/WifiConfigStore.xml.bak ~/evidence/stage5/
   adb pull /data/local/tmp/.sh_history ~/evidence/stage5/
   ```

2. **Extract EXIF & GPS Metadata from the Surveillance Photo**:
   Run `exiftool` against the captured camera image:
   ```bash
   exiftool ~/evidence/stage5/IMG_20261018_231405.jpg
   ```
   *Observation*: Examine `GPS Position`, `Artist`, `Image Description`, and `User Comment` to identify the exact GPS coordinates (`38° 53' 51.64" N, 77° 02' 11.58" W`) and the Stage 5 verification flag.

3. **Inspect the Harvested Wi-Fi Credentials**:
   ```bash
   cat ~/evidence/stage5/WifiConfigStore.xml.bak
   ```

4. **Analyze the Attacker's Root Shell History (`.sh_history`)**:
   ```bash
   cat ~/evidence/stage5/.sh_history
   ```
   * **Stage 5 Flag**: `FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}`
   * **Next Breadcrumb**: Look closely at the final commands in `.sh_history`:
     ```text
     tar -czf /data/local/tmp/.staging/.exfil_staging.tar.gz exfil_manifest.txt wire_transfer_approvals_Q4.csv
     openssl enc -aes-256-cbc -pbkdf2 -salt -in /data/local/tmp/.staging/crown_jewels.txt -out /data/local/tmp/.staging/crown_jewels.enc ...
     rm -f /data/local/tmp/.staging/crown_jewels.txt
     ```
     The attacker encrypted `crown_jewels.txt` into `/data/local/tmp/.staging/crown_jewels.enc` using `openssl enc -aes-256-cbc -pbkdf2` and the `staging_archive_key` stored in `auth_prefs.xml`, then deleted the plaintext file!

---

### Phase 6: Exfiltration Staging & Uncovering the Final Master Flag

#### Investigative Goal
Acquire the hidden staging directory `/data/local/tmp/.staging/`, inspect the unencrypted staging tarball, and decrypt `crown_jewels.enc` to capture the **Final Master Flag**.

#### Step-by-Step Procedure
1. **Acquire the Hidden Staging Directory**:
   ```bash
   adb shell ls -la /data/local/tmp/.staging/
   adb pull /data/local/tmp/.staging/.exfil_staging.tar.gz ~/evidence/stage6/
   adb pull /data/local/tmp/.staging/crown_jewels.enc ~/evidence/stage6/
   ```

2. **Extract and Review `.exfil_staging.tar.gz`**:
   ```bash
   tar -xzf ~/evidence/stage6/.exfil_staging.tar.gz -C ~/evidence/stage6/
   cat ~/evidence/stage6/exfil_manifest.txt
   cat ~/evidence/stage6/wire_transfer_approvals_Q4.csv
   ```

3. **Decrypt `crown_jewels.enc` to Capture the Final Master Flag**:
   Retrieve the `staging_archive_key` you discovered during **Phase 2** inside `/data/data/com.shadowvault.dropapp/shared_prefs/auth_prefs.xml` and run the OpenSSL decryption command:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 \
     -in ~/evidence/stage6/crown_jewels.enc \
     -out ~/evidence/stage6/crown_jewels.txt \
     -pass pass:<STAGING_ARCHIVE_KEY_FROM_AUTH_PREFS>
   ```

4. **Read the Decrypted Operational Dossier**:
   ```bash
   cat ~/evidence/stage6/crown_jewels.txt
   ```
   > [!NOTE]
   > **FINAL FLAG VERIFICATION**: Submit the `FINAL MASTER FLAG` (`FLAG{...}`) revealed at the bottom of `crown_jewels.txt` to complete the lab!

---

## Summary of Investigative Progress Checklist

| Phase | Mitre ATT&CK Mobile Tactic | Primary Artifact / Location | Stage Verification Flag |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Initial Access (Smishing) | `mmssms_forensic.db`, `contacts2_forensic.db`, `Chrome_History.db` | `FLAG{st4g3_1_sm1sh1ng_1n1t14l_4cc3ss}` |
| **Phase 2** | Execution & Dropper APK | `/sdcard/Download/ShadowDrop_v1.4.apk`, `auth_prefs.xml` | `FLAG{st4g3_2_apk_d3c0mp1l3d_dr0pp3r}` |
| **Phase 3** | Defense Evasion (`adb root`) | Global `settings`, `getprop`, `/system/etc/hosts`, `logcat` | `FLAG{st4g3_3_d3f3ns3_3v4s10n_r00t}` |
| **Phase 4** | Persistence & Masquerading | `/system/etc/init/shadowd.rc`, `/data/local/tmp/.sysd/kworker_netd` | `FLAG{st4g3_4_p3rs1st3nc3_1n1t_d43m0n}` |
| **Phase 5** | Collection & Reconnaissance | `/sdcard/DCIM/Camera/IMG_20261018_231405.jpg`, `.sh_history` | `FLAG{st4g3_5_3x1f_r3c0n_c0ll3ct10n}` |
| **Phase 6** | Exfiltration Vault Decryption | `/data/local/tmp/.staging/crown_jewels.enc` | `<FINAL_MASTER_FLAG>` *(Decrypt to reveal)* |

---

## Teardown

To stop and remove the lab containers:
```bash
docker compose down
```

To remove the built images and clear extracted volumes:
```bash
docker compose down -v --rmi local
```
