#!/usr/bin/env bash
# Boot the Wyze test emulator headless in its own cgroup (systemd user scope
# wyze-emu.scope), so test firewall rules can match just its traffic.
# usage: bash emu-start.sh
set -eu
# first time: nix-build live/android.nix -o $EMU_HOME/sdk, then install the
# app: live/emu.sh install-multiple <the .apkm's base.apk and splits>
export ANDROID_SDK_ROOT=${EMU_HOME:-$HOME/wyze-emu}/sdk/libexec/android-sdk
export ANDROID_HOME=$ANDROID_SDK_ROOT ANDROID_AVD_HOME=${EMU_HOME:-$HOME/wyze-emu}/avd
S=$ANDROID_SDK_ROOT
export XDG_RUNTIME_DIR=/run/user/$(id -u)
systemctl --user stop wyze-emu.scope 2>/dev/null || true
systemd-run --user --scope --unit wyze-emu -q \
  setsid nohup $S/emulator/emulator -avd wyze -no-window -no-audio -no-boot-anim \
   -gpu swiftshader_indirect -no-snapshot-save > ${EMU_HOME:-$HOME/wyze-emu}/emulator.log 2>&1 < /dev/null &
sleep 1
$S/platform-tools/adb -e wait-for-device < /dev/null
for i in $(seq 1 60); do
  [ "$($S/platform-tools/adb -e shell getprop sys.boot_completed < /dev/null | tr -d '\r')" = 1 ] && break; sleep 2
done
echo "booted; cgroup: $(cat /proc/$(pgrep -f 'qemu-system.*-avd wyze' | head -1)/cgroup)"
