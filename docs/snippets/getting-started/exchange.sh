export QAS_CALLBACK
unset QAS_ACCESS_TOKEN QAS_TOKEN_RESPONSE

QAS_CODE=$(python3 - <<'PY'
import os, sys
from urllib.parse import parse_qs, urlsplit

callback = urlsplit(os.environ["QAS_CALLBACK"])
params = parse_qs(callback.query)
if (callback.scheme, callback.netloc, callback.path) != ("http", "localhost:8080", "/callback.html"):
    sys.exit("Unexpected callback URL")
if params.get("state") != [os.environ["QAS_STATE"]]:
    sys.exit("State mismatch: restart authorization")
if "error" in params:
    sys.exit("Authorization failed: " + params["error"][0])
codes = params.get("code", [])
if len(codes) != 1:
    sys.exit("Expected one authorization code")
print(codes[0])
PY
) && QAS_TOKEN_RESPONSE=$(curl --fail-with-body -sS \
  -u quickstart-client:quickstart-secret \
  --data-urlencode grant_type=authorization_code \
  --data-urlencode redirect_uri=http://localhost:8080/callback.html \
  --data-urlencode "code=$QAS_CODE" \
  http://localhost:8080/oauth2/token) && \
QAS_ACCESS_TOKEN=$(printf '%s' "$QAS_TOKEN_RESPONSE" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
