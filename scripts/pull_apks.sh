#!/bin/bash

for package in $(adb shell pm list packages | tr -d '\r' | sed 's/package://g'); do
  apk=$(adb shell pm path $package | tr -d '\r' | sed 's/package://g');
  echo "Pulling $apk";
  adb pull -p "$apk";
done