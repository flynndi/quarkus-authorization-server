package io.quarkiverse.authorization.server.deployment;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Calls the actual Dev UI transport; no protocol request context or test-only REST resource is involved. */
final class DevUIJsonRpcClient {
    static JsonNode overview(String path, String tenantId) throws Exception {
        var mapper = new ObjectMapper();
        var request = mapper.createObjectNode().put("jsonrpc", "2.0").put("id", 1)
                .put("method", "quarkus-authorization-server_getOverview");
        request.putObject("params").put("tenantId", tenantId);
        var response = new CompletableFuture<JsonNode>();
        try (var client = HttpClient.newHttpClient()) {
            WebSocket socket = client.newWebSocketBuilder().connectTimeout(Duration.ofSeconds(10))
                    .buildAsync(URI.create("ws://localhost:8080" + path), new WebSocket.Listener() {
                        private final StringBuilder message = new StringBuilder();

                        @Override
                        public void onOpen(WebSocket webSocket) {
                            webSocket.request(1);
                        }

                        @Override
                        public java.util.concurrent.CompletionStage<?> onText(WebSocket webSocket, CharSequence data,
                                boolean last) {
                            this.message.append(data);
                            if (last) {
                                try {
                                    var json = mapper.readTree(this.message.toString());
                                    if (json.path("id").asInt() == 1)
                                        response.complete(json);
                                } catch (Exception exception) {
                                    response.completeExceptionally(exception);
                                }
                                this.message.setLength(0);
                            }
                            webSocket.request(1);
                            return null;
                        }

                        @Override
                        public void onError(WebSocket webSocket, Throwable error) {
                            response.completeExceptionally(error);
                        }
                    }).get(10, TimeUnit.SECONDS);
            try {
                socket.sendText(mapper.writeValueAsString(request), true).get(10, TimeUnit.SECONDS);
                return response.get(10, TimeUnit.SECONDS);
            } finally {
                socket.abort();
            }
        }
    }
}
