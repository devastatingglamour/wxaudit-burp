#!/bin/bash
set -e
cd "$(dirname "$0")"

BURP_ROOT="/d/webtool/BurpSuite V2024.9.1"
# Windows JVM needs a drive-letter classpath (MSYS does not translate a variable passed as one arg)
API_JAR="D:/webtool/BurpSuite V2024.9.1/BurpSuite/burpsuite_pro_org.jar"

# Compile in place (no directory deletion) so build output stays sandbox-friendly
mkdir -p stub-out out test-out

echo "=== 1. compile API stubs ==="
javac -encoding UTF-8 -d stub-out stub/burp/*.java

echo "=== 2. compile extension (stub bytecode isolated) ==="
javac -encoding UTF-8 -cp stub-out -d out src/wxaudit/*.java

echo "=== 3. compile tests ==="
javac -encoding UTF-8 -cp "stub-out;out" -d test-out test/wxaudit/*.java

echo "=== 4. core self-test (JDK8) ==="
java -cp "out;stub-out;test-out" wxaudit.SelfTest

echo "=== 4b. end-to-end passive scan (mocked Burp) ==="
java -Djava.awt.headless=true -cp "out;stub-out;test-out" wxaudit.IntegrationTest

echo "=== 4c. boundary / malformed input ==="
java -Djava.awt.headless=true -cp "out;stub-out;test-out" wxaudit.EdgeCaseTest

echo "=== 5. Burp API compatibility (Burp JRE21 + real jar) ==="
"$BURP_ROOT/jre/bin/java" -cp "$API_JAR;out;test-out" wxaudit.CompatCheck

echo "=== 6. package jar (wxaudit classes only, no stubs, reproducible) ==="
# pack.py writes ZIP entries with fixed timestamps; `jar cf` uses wall clock
# and would make two identical builds produce different SHA256 hashes.
python pack.py
jar tf wxaudit-burp.jar

echo ""
echo "BUILD OK -> $(pwd)/wxaudit-burp.jar"
