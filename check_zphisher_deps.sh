#!/bin/bash
# Zphisher dependency and environment check

echo "Checking Zphisher dependencies..."
for dep in php curl wget git openssh ngrok; do
  if ! command -v $dep &>/dev/null; then
    echo "Missing: $dep"
  else
    echo "Found: $dep"
  fi
done

if [ -f ./zphisher/zphisher.sh ]; then
  echo "zphisher.sh found and permissions: $(ls -l ./zphisher/zphisher.sh)"
else
  echo "zphisher.sh not found in ./zphisher/"
fi

if [ -d ./zphisher/.sites ]; then
  echo ".sites directory is present and readable."
else
  echo ".sites directory missing or not readable."
fi

if command -v ngrok &>/dev/null; then
  ngrok config check || echo "ngrok config may be missing or invalid."
fi 