FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV USER=investigator
ENV HOME=/home/investigator
ENV DISPLAY=:1
ENV VNC_PORT=5901
ENV NOVNC_PORT=6081
ENV VNC_RESOLUTION=1920x1080
ENV ANDROID_TARGET_HOST=172.28.0.10
ENV ANDROID_TARGET_PORT=5555

# 1. Install Desktop GUI (XFCE4 + TigerVNC + noVNC) & System Utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    xfce4 \
    xfce4-goodies \
    xfce4-terminal \
    dbus-x11 \
    x11-xserver-utils \
    tigervnc-standalone-server \
    tigervnc-common \
    novnc \
    websockify \
    openssh-server \
    sudo \
    curl \
    wget \
    git \
    vim \
    nano \
    unzip \
    zip \
    tar \
    gzip \
    bzip2 \
    p7zip-full \
    procps \
    net-tools \
    iputils-ping \
    iproute2 \
    netcat-traditional \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. Install Mobile & Digital Forensics Toolkit
RUN apt-get update && apt-get install -y --no-install-recommends \
    adb \
    fastboot \
    apktool \
    jadx \
    dex2jar \
    sqlite3 \
    sqlitebrowser \
    sleuthkit \
    binwalk \
    foremost \
    libimage-exiftool-perl \
    yara \
    radare2 \
    hexedit \
    ghex \
    binutils \
    file \
    xxd \
    tshark \
    wireshark \
    tcpdump \
    default-jdk-headless \
    python3 \
    python3-pip \
    python3-pil \
    python3-cryptography \
    && rm -rf /var/lib/apt/lists/*

# 3. Install Python Mobile Forensics / Reverse Engineering packages
RUN pip3 install --no-cache-dir --break-system-packages \
    piexif \
    androguard \
    frida-tools || true

# 4. Configure OpenSSH Server on port 2222
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "Port 2222" >> /etc/ssh/sshd_config && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# 5. Create Investigator User & Configure Sudo
RUN useradd -m -s /bin/bash investigator && \
    echo "investigator:forensics" | chpasswd && \
    echo "root:forensics" | chpasswd && \
    usermod -aG sudo investigator && \
    echo "investigator ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# 6. Configure noVNC index redirect so http://localhost:6081 opens directly
RUN ln -sf /usr/share/novnc/vnc.html /usr/share/novnc/index.html

# 7. Copy Forensic Artifact Generator & Android Seeding Scripts
RUN mkdir -p /opt/forensics-seeder /home/investigator/evidence /home/investigator/Desktop
COPY scripts/generate_artifacts.py /opt/forensics-seeder/generate_artifacts.py
COPY scripts/seed_android.sh /opt/forensics-seeder/seed_android.sh
COPY entrypoint.sh /entrypoint.sh

# Normalize line endings and permissions
RUN sed -i 's/\r$//' /opt/forensics-seeder/seed_android.sh /entrypoint.sh && \
    chmod +x /opt/forensics-seeder/seed_android.sh /opt/forensics-seeder/generate_artifacts.py /entrypoint.sh

# 8. Pre-generate the Forensic Artifacts during build so they are ready immediately
RUN python3 /opt/forensics-seeder/generate_artifacts.py /opt/forensics-seeder/artifacts

# 9. Create Desktop Shortcuts for GUI Forensics Tools
RUN cat << 'EOF' > /home/investigator/Desktop/SQLiteBrowser.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=DB Browser for SQLite
Comment=Inspect Android SQLite Databases
Exec=sqlitebrowser /home/investigator/evidence
Icon=sqlitebrowser
Terminal=false
StartupNotify=false
EOF
RUN cat << 'EOF' > /home/investigator/Desktop/JADX-GUI.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=JADX APK Decompiler
Comment=Decompile Android APKs to Java Source
Exec=jadx-gui
Icon=utilities-terminal
Terminal=false
StartupNotify=false
EOF
RUN cat << 'EOF' > /home/investigator/Desktop/Forensics-Terminal.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=Forensics Terminal
Comment=Open Terminal in Evidence Directory
Exec=xfce4-terminal --working-directory=/home/investigator/evidence
Icon=utilities-terminal
Terminal=false
StartupNotify=false
EOF
RUN chmod +x /home/investigator/Desktop/*.desktop && \
    chown -R investigator:investigator /home/investigator

WORKDIR /home/investigator/evidence

EXPOSE 6081 5901 2222

ENTRYPOINT ["/entrypoint.sh"]
