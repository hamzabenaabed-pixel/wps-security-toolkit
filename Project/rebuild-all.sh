#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# rebuild-all.sh — يعيد بناء Bettercap Console كاملاً من الصفر
# يعالج خسارة اللقطات لـ: .toolchain + node_modules + engine assets
# الاستخدام: bash ~/rebuild-all.sh 2>&1 | tee rebuild.log
# ═══════════════════════════════════════════════════════════════
set -e
TC=/home/user/.toolchain; ARM=$TC/arm; PRJ=/home/user/bettercap-project/android
E=$PRJ/app/src/main/assets/engine
GREEN='\033[0;32m'; NC='\033[0m'; say(){ echo -e "${GREEN}==> $1${NC}"; }

say "0) Swap (ضد OOM)"
sudo -n swapon /swapfile 2>/dev/null || true

say "1) JDK21 + cmdline-tools + Go + مصدر bettercap"
mkdir -p $TC $ARM
[ -x $TC/jdk21/bin/java ] || { cd $TC && curl -sL -o j.tgz "https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse" && tar xzf j.tgz && mv jdk-21* jdk21 && rm j.tgz; }
[ -x $TC/android-sdk/cmdline-tools/latest/bin/sdkmanager ] || { cd $TC && curl -sL -o ct.zip "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip" && unzip -q ct.zip && mkdir -p android-sdk/cmdline-tools/latest && cp -r cmdline-tools/* android-sdk/cmdline-tools/latest/ && rm -rf ct.zip cmdline-tools; }
[ -x $ARM/go/bin/go ] || { cd $ARM && curl -sL -o g.tgz "https://go.dev/dl/go1.24.5.linux-amd64.tar.gz" && tar xzf g.tgz && rm g.tgz; }
[ -d $ARM/bc-src ] || { cd $ARM && curl -sL -o s.tgz "https://github.com/bettercap/bettercap/archive/refs/tags/v2.41.7.tar.gz" && tar xzf s.tgz && mv bettercap-2.41.7 bc-src && rm s.tgz; }

say "2) حزم Android SDK 35"
export JAVA_HOME=$TC/jdk21; export ANDROID_HOME=$TC/android-sdk; export PATH=$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ARM/go/bin:$PATH
[ -d $ANDROID_HOME/platforms/android-35 ] || { yes | $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1; $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager "platforms;android-35" "build-tools;35.0.0" "platform-tools" >/dev/null; }

say "3) NDK r27 (لـ bettercap ARM64)"
[ -d $ARM/ndk ] || { cd $ARM && curl -sL -o ndk.zip "https://dl.google.com/android/repository/android-ndk-r27-linux.zip" && unzip -q ndk.zip && mv android-ndk-r27 ndk && rm ndk.zip; }

say "4) حزم Termux (nmap + مكتبات bionic)"
ENGD=$ARM/engine/data/data/com.termux/files/usr
if [ ! -f $ENGD/lib/libpcap.so.1 ]; then
  mkdir -p $ARM/debs $ARM/engine && cd $ARM/debs
  M="https://packages-cf.termux.dev/apt/termux-main"
  for u in "$M/pool/main/n/nmap/nmap_7.99-1_aarch64.deb" "$M/pool/main/libp/libpcap/libpcap_1.10.5-1_aarch64.deb" "$M/pool/main/libu/libusb/libusb_1.0.30_aarch64.deb" "$M/pool/main/libc/libc++/libc++_29_aarch64.deb" "$M/pool/main/l/lua54/lua54_5.4.8-7_aarch64.deb" "$M/pool/main/libs/libssh2/libssh2_1.11.1-2_aarch64.deb" "$M/pool/main/o/openssl/openssl_1:3.6.3_aarch64.deb" "$M/pool/main/p/pcre2/pcre2_10.47_aarch64.deb" "$M/pool/main/z/zlib/zlib_1.3.2_aarch64.deb"; do
    f=$(basename "$u"); f=${f//:/_}; curl -sL -o "$f" "$u"; ar x "$f"; tar xf data.tar.* -C $ARM/engine 2>/dev/null || true; rm -f data.tar.* control.tar.* debian-binary;
  done
fi

say "5) بناء bettercap 2.41.7 لـ android/arm64"
if [ ! -f $ARM/engine-bin/bettercap ]; then
  sed -i "s|/data/data/com.termux/files/usr|$ENGD|g" $ENGD/lib/pkgconfig/*.pc
  cd $ARM/bc-src
  export GOPATH=/home/user/.go-work/path GOCACHE=/home/user/.go-work/cache GOTMPDIR=/home/user/.go-work/tmp GOENV=off GOFLAGS=-mod=mod GOGC=60 GOPROXY=https://proxy.golang.org,direct GOSUMDB=off
  NDK=$ARM/ndk/toolchains/llvm/prebuilt/linux-x86_64
  CGO_ENABLED=1 GOOS=android GOARCH=arm64 CC=$NDK/bin/aarch64-linux-android24-clang CXX=$NDK/bin/aarch64-linux-android24-clang++ \
  CGO_CFLAGS="-I$ENGD/include -I$ENGD/include/libusb-1.0" CGO_LDFLAGS="-L$ENGD/lib -Wl,-rpath-link,$ENGD/lib -L$NDK/sysroot/usr/lib/aarch64-linux-android/24" \
  PKG_CONFIG_LIBDIR=$ENGD/lib/pkgconfig go build -p 2 -trimpath -ldflags="-s -w" -o $ARM/engine-bin/bettercap .
fi

say "6) تجميع أصول المحرك داخل المشروع"
rm -rf /tmp/caplets && git clone --depth 1 -q https://github.com/bettercap/caplets.git /tmp/caplets
mkdir -p $E/bin $E/lib $E/share
cp $ARM/engine-bin/bettercap $E/bin/
cp $ENGD/bin/nmap $ENGD/bin/nping $ENGD/bin/openssl $E/bin/ 2>/dev/null || true
cp $ENGD/lib/libpcap.so* $ENGD/lib/libusb-1.0.so* $ENGD/lib/libc++_shared.so $ENGD/lib/liblua5.4.so* $ENGD/lib/libssl.so* $ENGD/lib/libcrypto.so* $ENGD/lib/libssh2.so* $ENGD/lib/libpcre2-8.so* $ENGD/lib/libz.so* $E/lib/
cp -r $ENGD/share/nmap $E/share/ 2>/dev/null || true
rm -rf $E/share/bettercap/caplets && mkdir -p $E/share/bettercap/caplets && cp -r /tmp/caplets/* $E/share/bettercap/caplets/
rm -rf $E/share/bettercap/caplets/.git $E/share/bettercap/caplets/download-autopwn $E/share/bettercap/caplets/hstshijack
find $E/share/bettercap/caplets -type f ! -name "*.cap" -delete 2>/dev/null; find $E/share/bettercap/caplets -type d -empty -delete

say "7) استرجاع @capacitor/android (node_modules يُحذف دائماً)"
if [ ! -f /home/user/bettercap-project/node_modules/@capacitor/android/capacitor/build.gradle ]; then
  cd /tmp && npm pack "@capacitor/android@8.4.2" --silent >/dev/null 2>&1 || true
  mkdir -p /home/user/bettercap-project/node_modules/@capacitor/android
  tar xzf capacitor-android-8.4.2.tgz -C /home/user/bettercap-project/node_modules/@capacitor/android --strip-components=1
fi

[ "$1" = "core" ] && { echo "==> CORE_DONE"; exit 0; }
say "8) بناء APK + توقيع"
cd $PRJ && chmod +x gradlew
./gradlew :app:assembleRelease --no-daemon --console=plain -x lint -x lintVitalRelease -x test
BT=$ANDROID_HOME/build-tools/35.0.0
$BT/zipalign -p -f -v 4 app/build/outputs/apk/release/app-release-unsigned.apk /tmp/final.apk >/dev/null
$BT/apksigner sign --ks /home/user/bettercap-keystore.jks --ks-pass pass:bettercap123 --key-pass pass:bettercap123 \
  --v1-signing-enabled true --v2-signing-enabled true --v3-signing-enabled true \
  --out /home/user/Bettercap-Console-REBUILT.apk /tmp/final.apk
rm -f /tmp/final.apk
say "✅ تم! /home/user/Bettercap-Console-REBUILT.apk"
ls -lh /home/user/Bettercap-Console-REBUILT.apk
