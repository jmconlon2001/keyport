#!/usr/bin/env bash
# Re-render the README diagrams to PNG after editing a .mmd file here.
# PNGs (not live Mermaid) so they also display in the GitHub mobile app.
# Needs Node.js; mermaid-cli downloads its own headless Chrome unless PUPPETEER_EXECUTABLE_PATH is set.
set -euo pipefail
cd "$(dirname "$0")"
for f in *.mmd; do
  npx -y -p @mermaid-js/mermaid-cli@11.4.2 mmdc -q -c mermaid-config.json -b white -s 2 \
    -i "$f" -o "../images/diagram-${f%.mmd}.png"
done
