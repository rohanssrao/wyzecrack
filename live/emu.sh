#!/usr/bin/env bash
# helpers for the Wyze test emulator; usage: bash emu.sh <cmd> [args]
A=${EMU_HOME:-$HOME/wyze-emu}/sdk/libexec/android-sdk/platform-tools/adb
adb() { $A -e "$@" < /dev/null; }
case $1 in
  shot)   adb exec-out screencap -p > ${2:-/tmp/emu.png}; echo "${2:-/tmp/emu.png}" ;;
  launch) adb shell monkey -p com.hualai -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 ;;
  tap)    adb shell input tap $2 $3 ;;
  text)   adb shell input text "$2" ;;
  key)    adb shell input keyevent $2 ;;
  swipe)  adb shell input swipe $2 $3 $4 $5 ${6:-300} ;;
  top)    adb shell dumpsys activity activities | grep -m1 -E "topResumedActivity|mResumedActivity" ;;
  ui)     adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1; adb exec-out cat /sdcard/ui.xml ;;
  stop)   adb shell am force-stop com.hualai ;;
  *)      adb "$@" ;;
esac
