#!/usr/bin/env bash
# Restart the emulator with a visible window on a virtual X display, and
# serve that display as a password-protected noVNC page on this host's tailnet
# address only. usage: bash emu-screen.sh start|stop
set -u
D=:57
TS=$(tailscale ip -4)
W=${EMU_HOME:-$HOME/wyze-emu}
stop_all() {
  pkill -f "websockify.*6080"; pkill -f "x11vnc -display $D"; pkill -f "Xvfb $D"
}
case ${1:-start} in
stop) stop_all; exit 0 ;;
esac
stop_all
export ANDROID_SDK_ROOT=$W/sdk/libexec/android-sdk ANDROID_HOME=$W/sdk/libexec/android-sdk ANDROID_AVD_HOME=$W/avd
S=$ANDROID_SDK_ROOT
$S/platform-tools/adb -e emu kill < /dev/null >/dev/null 2>&1; sleep 3
pkill -f "qemu-system.*-avd wyze"; sleep 1
XVFB=$(nix build --no-link --print-out-paths nixpkgs#xorg.xorgserver)/bin/Xvfb
X11VNC=$(nix build --no-link --print-out-paths nixpkgs#x11vnc)/bin/x11vnc
XCBC=$(nix build --no-link --print-out-paths nixpkgs#xcb-util-cursor)/lib
if [ ! -d $W/novnc ]; then
  curl -sSL https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.tar.gz | tar xz -C $W
  mv $W/noVNC-1.5.0 $W/novnc
fi
setsid nohup $XVFB $D -screen 0 720x1440x24 -nolisten tcp > $W/xvfb.log 2>&1 < /dev/null &
sleep 2
DISPLAY=$D LD_LIBRARY_PATH=$XCBC setsid nohup $S/emulator/emulator -avd wyze -no-audio -no-boot-anim \
  -gpu swiftshader_indirect -no-snapshot-save -scale 0.55 > $W/emulator.log 2>&1 < /dev/null &
PASS=$(head -c 12 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 8)
mkdir -p $W/vnc && chmod 700 $W/vnc
$X11VNC -storepasswd "$PASS" $W/vnc/passwd >/dev/null 2>&1
setsid nohup $X11VNC -display $D -rfbauth $W/vnc/passwd -localhost -rfbport 5957 -forever -shared > $W/x11vnc.log 2>&1 < /dev/null &
setsid nohup uvx --quiet websockify --web $W/novnc $TS:6080 127.0.0.1:5957 > $W/websockify.log 2>&1 < /dev/null &
sleep 4
echo "url: http://$TS:6080/vnc.html  password: $PASS"
