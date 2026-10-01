package io.quarkiverse.authorization.server.runtime.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import javax.sql.DataSource;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;

import io.quarkiverse.authorization.server.jdbc.JdbcJsonCodec;
import io.quarkiverse.authorization.server.jdbc.JdbcJsonValueAdapter;

public final class JdbcTestSupport {

    private JdbcTestSupport() {
    }

    public static JdbcJsonCodec jsonCodec() {
        return new JdbcJsonCodec(List.of(new JdbcJsonValueAdapter<CustomValue>() {
            public String typeId() {
                return "custom:test-value";
            }

            public Class<CustomValue> javaType() {
                return CustomValue.class;
            }

            public JsonNode write(CustomValue value) {
                return TextNode.valueOf(value.value());
            }

            public CustomValue read(JsonNode value) {
                if (!value.isTextual())
                    throw new IllegalArgumentException("Expected custom value text");
                return new CustomValue(value.textValue());
            }
        }));
    }

    public record CustomValue(String value) {
    }

    public static void executeSchema(DataSource dataSource, String location) {
        String sql;
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream(location)) {
            if (input == null) {
                throw new IllegalStateException("Schema resource not found: " + location);
            }
            sql = new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read schema resource: " + location, exception);
        }
        try (Connection connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
            for (String command : sql.split(";")) {
                if (!command.isBlank()) {
                    statement.execute(command);
                }
            }
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to execute schema resource: " + location, exception);
        }
    }
}
