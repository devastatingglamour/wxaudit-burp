#!/bin/bash
# Three-round sandbox acceptance. Nothing is published unless all three pass.
set -e
cd "$(dirname "$0")"

JRE="/d/webtool/BurpSuite V2024.9.1/jre/bin/java"
API_JAR="D:/webtool/BurpSuite V2024.9.1/BurpSuite/burpsuite_pro_org.jar"

echo "############################################################"
echo "# ROUND 1 - full build: core / integration / edge / API compat"
echo "############################################################"
bash build.sh 2>&1 | tee verification-round1.log
grep -q "ALL CORE SELF-TESTS PASSED" verification-round1.log
grep -q "INTEGRATION TEST PASSED" verification-round1.log
grep -q "EDGE CASE TEST PASSED" verification-round1.log
grep -q "AI MOCK TEST PASSED" verification-round1.log
grep -q "BURP API COMPATIBILITY OK" verification-round1.log
grep -q "BUILD OK" verification-round1.log
echo ">>> ROUND 1 PASS"

echo ""
echo "############################################################"
echo "# ROUND 2 - repeatability + artifact integrity"
echo "############################################################"
HASH1=$(sha256sum wxaudit-burp.jar | awk '{print $1}')
bash build.sh 2>&1 | tee verification-round2.log
HASH2=$(sha256sum wxaudit-burp.jar | awk '{print $1}')
echo "  SHA256 round1 = $HASH1"
echo "  SHA256 round2 = $HASH2"
test "$HASH1" = "$HASH2" || { echo "FAIL: jar not reproducible"; exit 1; }
echo "  OK   jar is byte-for-byte reproducible"

if jar tf wxaudit-burp.jar | grep -q '^burp/'; then
  echo "FAIL: stub classes leaked into delivered jar"; exit 1
fi
echo "  OK   no stub burp/*.class in delivered jar"
CLASSES=$(jar tf wxaudit-burp.jar | grep -c '\.class$')
echo "  OK   delivered jar contains $CLASSES classes"
SIZE=$(stat -c%s wxaudit-burp.jar)
test "$SIZE" -gt 30000 || { echo "FAIL: jar suspiciously small"; exit 1; }
echo "  OK   jar size = $SIZE bytes"
echo ">>> ROUND 2 PASS"

echo ""
echo "############################################################"
echo "# ROUND 3 - load delivered jar on Burp JRE21 + real API jar"
echo "############################################################"
"$JRE" -Djava.awt.headless=true -cp "$API_JAR;wxaudit-burp.jar;test-out" wxaudit.JarLoadTest 2>&1 | tee verification-round3.log
grep -q "JAR LOAD TEST PASSED" verification-round3.log
echo ">>> ROUND 3 PASS"

echo ""
echo "================================================================"
echo "ALL THREE ROUNDS PASSED - SAFE TO PUBLISH"
echo "  artifact: $(pwd)/wxaudit-burp.jar"
echo "  sha256:   $HASH2"
echo "================================================================"
