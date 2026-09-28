package io.quarkiverse.authorization.server.runtime.jdbc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import javax.sql.DataSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import io.quarkiverse.authorization.server.runtime.jackson2.OAuth2AuthorizationServerJackson2Module;

public final class JdbcTestSupport {

    private JdbcTestSupport() {
    }

    public static ObjectMapper objectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .registerModule(new OAuth2AuthorizationServerJackson2Module());
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
