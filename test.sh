#!/bin/bash
cd "/mnt/c/Users/lenovo/Documents/Software Provenance Tracker"
fuser -k 8000/tcp 2>/dev/null
sleep 2
python3 backend/main.py > /tmp/sdpt_prod.log 2>&1 &
sleep 20
curl -s http://localhost:8000/health | python3 -m json.tool
curl -s -X POST http://localhost:8000/api/dependencies/scan \
  -H "X-API-Key: sdpt-dev-key-2024" \
  -H "Content-Type: application/json" \
  -d '{"content":"requests","file_type":"requirements.txt","project_name":"prod-test"}' \
  | python3 -m json.tool | head -5
ls -la logs/
