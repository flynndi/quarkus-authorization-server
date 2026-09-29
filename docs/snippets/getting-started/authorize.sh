export QAS_STATE=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

printf '%s\n' "http://localhost:8080/oauth2/authorize?response_type=code&client_id=quickstart-client&redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fcallback.html&scope=message.read&state=$QAS_STATE"
