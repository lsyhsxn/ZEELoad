#!/bin/bash
# ZEELoad 改包名 + 重签名工具（一步到位，产出 v1+v2+v3 签名的伪装 APK）
#
# 用途：把任意 APK 的包名改成极氪应用市场上架的包名（如 com.netease.cloudmusic.iot），
#       绕过车机「仅支持上架应用」的白名单，并用 apksigner 生成 v2/v3 签名。
#
# 关键点：车机 targetSdkVersion>=30 的应用必须使用 v2 及以上签名，
#         只用 jarsigner（v1）会导致车机安装器报「安装失败，请重试」。
#
# 用法：
#   ./repack-sign.sh <原始APK> <新包名> [输出文件名]
#
# 依赖（本目录内自带，免安装）：
#   jdk-17.0.21+9/          免安装 JDK17（含 apksigner / zipalign / keytool）
#   apktool.jar             apktool 2.9.3
#   sign.jks                签名密钥（别名 zeeload，密码 zeeload123）
#
# 示例：
#   ./repack-sign.sh 酷我.apk com.netease.cloudmusic.iot 网易云音乐伪装包.apk

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
JDK_HOME="$HERE/jdk-17.0.21+9/Contents/Home"
export JAVA_HOME="$JDK_HOME"
export PATH="$JDK_HOME/bin:$PATH"

APK_IN="${1:?用法: $0 <原始APK> <新包名> [输出文件名]}"
NEW_PKG="${2:?用法: $0 <原始APK> <新包名> [输出文件名]}"
OUT_NAME="${3:-$(basename "$APK_IN" .apk)_伪装_${NEW_PKG}.apk}"

APK_IN_ABS="$(cd "$(dirname "$APK_IN")" && pwd)/$(basename "$APK_IN")"
WORK="$HERE/_repack_work"
rm -rf "$WORK"
mkdir -p "$WORK"

echo "==> [1/6] 反编译 APK（apktool）"
java -jar "$HERE/apktool.jar" d -f "$APK_IN_ABS" -o "$WORK/decoded"

echo "==> [2/6] 读取原包名"
OLD_PKG=$(grep -oE 'package="[^"]+"' "$WORK/decoded/AndroidManifest.xml" | head -1 | sed 's/package="//;s/"//')
echo "    原包名: $OLD_PKG"
echo "    新包名: $NEW_PKG"

echo "==> [3/6] 修改 AndroidManifest.xml 主包名"
# manifest 根节点 package
sed -i '' "s/package=\"$OLD_PKG\"/package=\"$NEW_PKG\"/g" "$WORK/decoded/AndroidManifest.xml"

echo "==> [4/6] 同步修改资源文件里的 namespace 声明"
# apktool 会把部分资源里的 xmlns:app="...res/<旧包名>" 保留，需一并替换
grep -rl "res/$OLD_PKG" "$WORK/decoded/res" 2>/dev/null | while read -r f; do
  sed -i '' "s|res/$OLD_PKG|res/$NEW_PKG|g" "$f"
  echo "    修正: $f"
done

echo "==> [5/6] 重打包（apktool b）"
java -jar "$HERE/apktool.jar" b "$WORK/decoded" -o "$WORK/repacked.apk"

echo "==> [6/6] zipalign + apksigner（生成 v1+v2+v3 签名）"
zipalign -f -p 4 "$WORK/repacked.apk" "$WORK/aligned.apk"
apksigner sign \
  --ks "$HERE/sign.jks" \
  --ks-key-alias zeeload \
  --ks-pass pass:zeeload123 \
  --key-pass pass:zeeload123 \
  --out "$WORK/signed.apk" \
  "$WORK/aligned.apk"

echo "==> 校验签名"
apksigner verify --verbose "$WORK/signed.apk" | grep -E "Verifies|v2 scheme|v3 scheme"

# 输出到用户指定路径
cp "$WORK/signed.apk" "$OUT_NAME"

echo ""
echo "======================================================"
echo "完成！伪装 APK 已生成："
echo "  $(cd "$(dirname "$OUT_NAME")" && pwd)/$(basename "$OUT_NAME")"
echo ""
echo "签名信息：v1 + v2 + v3（满足 targetSdkVersion>=30 要求）"
echo "======================================================"
