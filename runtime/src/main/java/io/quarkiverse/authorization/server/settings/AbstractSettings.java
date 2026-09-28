package io.quarkiverse.authorization.server.settings;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import io.quarkiverse.authorization.server.runtime.util.Arguments;

/**
 * Base implementation for configuration settings.
 */
public abstract class AbstractSettings implements Serializable {

    @Serial
    private static final long serialVersionUID = -2100741569870032293L;

    private final Map<String, Object> settings;

    protected AbstractSettings(Map<String, Object> settings) {
        if (settings == null || settings.isEmpty()) {
            throw new IllegalArgumentException("settings cannot be empty");
        }
        this.settings = Collections.unmodifiableMap(new HashMap<>(settings));
    }

    @SuppressWarnings("unchecked")
    public <T> T getSetting(String name) {
        Arguments.requireNonBlank(name, "name");
        return (T) this.settings.get(name);
    }

    public Map<String, Object> getSettings() {
        return this.settings;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        return object != null && getClass() == object.getClass()
                && this.settings.equals(((AbstractSettings) object).settings);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.settings);
    }

    @Override
    public String toString() {
        return "AbstractSettings {settings=" + this.settings + "}";
    }

    protected abstract static class AbstractBuilder<T extends AbstractSettings, B extends AbstractBuilder<T, B>> {

        private final Map<String, Object> settings = new HashMap<>();

        public B setting(String name, Object value) {
            Arguments.requireNonBlank(name, "name");
            this.settings.put(name, Objects.requireNonNull(value, "value cannot be null"));
            return getThis();
        }

        public B settings(Consumer<Map<String, Object>> settingsConsumer) {
            Objects.requireNonNull(settingsConsumer, "settingsConsumer cannot be null").accept(this.settings);
            return getThis();
        }

        public abstract T build();

        protected final Map<String, Object> getSettings() {
            return this.settings;
        }

        @SuppressWarnings("unchecked")
        protected final B getThis() {
            return (B) this;
        }
    }
}
