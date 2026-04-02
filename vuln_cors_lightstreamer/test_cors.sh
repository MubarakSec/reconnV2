#!/bin/bash
TARGET="https://push-lightstreamer.cloud.etoro.com/lightstreamer/create_session.txt"
ATTACKER_ORIGIN="https://evil-attacker.com"

echo "--- Testing CORS Misconfiguration on eToro ---"
echo "Target: $TARGET"
echo "Attacker Origin: $ATTACKER_ORIGIN"
echo ""

curl -i -s -k -X POST \
     -H "Origin: $ATTACKER_ORIGIN" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "LS_op=create" "$TARGET" | grep -E "HTTP/|access-control-allow-origin|access-control-allow-credentials"

echo ""
echo "Vulnerability confirmed if 'access-control-allow-origin' matches '$ATTACKER_ORIGIN' AND 'access-control-allow-credentials' is 'true'."
