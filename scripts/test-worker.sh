#!/bin/bash
set -e

export GHIDRA_HOME="${GHIDRA_HOME:-/Users/user/code/claude/ghidra-mcp/ghidra_12.0.2_PUBLIC}"
WORKER_JAR="ghidra-worker/build/libs/ghidra-worker-1.0.0.jar"

CP="$WORKER_JAR"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Generic/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/SoftwareModeling/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Project/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/FileSystem/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/DB/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Utility/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Docking/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Help/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Graph/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Gui/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Framework/Emulation/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Features/Base/lib/*"
CP="$CP:$GHIDRA_HOME/Ghidra/Features/Decompiler/lib/*"

java -cp "$CP" com.ghidramcp.Worker \
  --worker-id test-1 \
  --session-id test-session \
  --daemon-url http://localhost:9999 \
  --binary "$1" \
  --project /tmp/test-ghidra-project
