#!/bin/bash
set -e

echo "=================================================================="
echo "  Kali Linux Mobile Forensics Workstation Starting..."
echo "=================================================================="

VNC_PASS="${VNC_PASSWORD:-forensics}"
VNC_RES="${VNC_RESOLUTION:-1920x1080}"
VNC_DISPLAY=":1"
VNC_PORT="5901"
NOVNC_PORT="6081"

# 1. Generate SSH Host keys if missing and start OpenSSH Server
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "[+] Generating SSH host keys..."
    ssh-keygen -A
fi
echo "[+] Starting OpenSSH daemon on port 2222..."
/usr/sbin/sshd -p 2222

# 2. Configure VNC password and xstartup for user 'investigator'
echo "[+] Configuring TigerVNC & XFCE4 Desktop for user 'investigator'..."
mkdir -p /home/investigator/.vnc /home/investigator/evidence
echo "$VNC_PASS" | vncpasswd -f > /home/investigator/.vnc/passwd
chmod 600 /home/investigator/.vnc/passwd

cat << 'EOF' > /home/investigator/.vnc/xstartup
#!/bin/sh
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XKL_XMODMAP_DISABLE=1
exec dbus-launch --exit-with-session startxfce4
EOF
chmod +x /home/investigator/.vnc/xstartup
chown -R investigator:investigator /home/investigator/.vnc /home/investigator/evidence

# Clean up any stale VNC locks from previous container runs
rm -rf /tmp/.X1-lock /tmp/.X11-unix/X1

# 3. Launch TigerVNC Server on Display :1 (Port 5901)
echo "[+] Starting VNC Server on display ${VNC_DISPLAY} (${VNC_RES})..."
su - investigator -c "vncserver ${VNC_DISPLAY} -geometry ${VNC_RES} -depth 24 -localhost no"

# 4. Launch noVNC / websockify on port 6081
echo "[+] Starting noVNC Web GUI on port ${NOVNC_PORT}..."
websockify --web=/usr/share/novnc/ ${NOVNC_PORT} localhost:${VNC_PORT} >/var/log/novnc.log 2>&1 &

# 5. Launch Android ADB Evidence Seeder in background
echo "[+] Launching Android Forensic Evidence Seeder in background..."
/opt/forensics-seeder/seed_android.sh &

echo "=================================================================="
echo "  [+] Kali Forensics Web GUI : http://localhost:${NOVNC_PORT}/vnc.html"
echo "  [+] VNC / SSH Password     : ${VNC_PASS}"
echo "  [+] SSH Access             : ssh investigator@localhost -p 2222"
echo "  [+] Android Target ADB     : ${ANDROID_TARGET_HOST}:${ANDROID_TARGET_PORT}"
echo "=================================================================="

# Keep container alive and stream seeder log
touch /var/log/forensics-seeder.log /var/log/novnc.log
exec tail -f /var/log/forensics-seeder.log /var/log/novnc.log
