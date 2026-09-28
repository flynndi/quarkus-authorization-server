package io.quarkiverse.authorization.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Executable;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.lang.reflect.WildcardType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.Test;

import io.quarkiverse.authorization.server.client.RegisteredClient;

/** Checks signatures, including nested builders and generic bounds, without freezing implementation dependencies. */
class PublicApiBoundaryTest {
    private static final String BASE_PACKAGE = "io.quarkiverse.authorization.server.";

    @Test
    void publicSignaturesDoNotExposeInternalTypes() throws Exception {
        Path classes = Path.of(RegisteredClient.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        Set<String> violations = new TreeSet<>();
        try (var files = Files.walk(classes.resolve(BASE_PACKAGE.replace('.', '/')))) {
            var names = files.filter(path -> path.toString().endsWith(".class"))
                    .map(path -> classes.relativize(path).toString().replace('/', '.').replace('\\', '.'))
                    .map(name -> name.substring(0, name.length() - ".class".length()))
                    .filter(name -> !isInternal(name))
                    .toList();
            assertFalse(names.isEmpty(), "No API classes found in the runtime main output");
            for (String name : names) {
                Class<?> type = Class.forName(name, false, RegisteredClient.class.getClassLoader());
                if (!isVisible(type)) {
                    continue;
                }
                check(type.getGenericSuperclass(), name, new HashSet<>(), violations);
                for (Type parent : type.getGenericInterfaces()) {
                    check(parent, name, new HashSet<>(), violations);
                }
                for (Type parameter : type.getTypeParameters()) {
                    check(parameter, name, new HashSet<>(), violations);
                }
                for (var field : type.getDeclaredFields()) {
                    if (isVisible(field.getModifiers())) {
                        check(field.getGenericType(), field.toString(), new HashSet<>(), violations);
                    }
                }
                for (var constructor : type.getDeclaredConstructors()) {
                    check(constructor, violations);
                }
                for (var method : type.getDeclaredMethods()) {
                    if (isVisible(method.getModifiers())) {
                        check(method.getGenericReturnType(), method.toString(), new HashSet<>(), violations);
                        check(method, violations);
                    }
                }
            }
        }
        assertTrue(violations.isEmpty(), () -> "Public API exposes internal types:\n" + String.join("\n", violations));
    }

    private static void check(Executable member, Set<String> violations) {
        if (!isVisible(member.getModifiers())) {
            return;
        }
        Set<Type> visited = new HashSet<>();
        for (Type parameter : member.getTypeParameters()) {
            check(parameter, member.toString(), visited, violations);
        }
        for (Type parameter : member.getGenericParameterTypes()) {
            check(parameter, member.toString(), visited, violations);
        }
        for (Type exception : member.getGenericExceptionTypes()) {
            check(exception, member.toString(), visited, violations);
        }
    }

    private static void check(Type type, String declaration, Set<Type> visited, Set<String> violations) {
        if (type == null || !visited.add(type)) {
            return;
        }
        if (type instanceof Class<?> clazz) {
            if (clazz.isArray()) {
                check(clazz.getComponentType(), declaration, visited, violations);
            } else if (isInternal(clazz.getName())) {
                violations.add(declaration + " -> " + clazz.getName());
            }
        } else if (type instanceof ParameterizedType parameterized) {
            check(parameterized.getRawType(), declaration, visited, violations);
            check(parameterized.getOwnerType(), declaration, visited, violations);
            for (Type argument : parameterized.getActualTypeArguments()) {
                check(argument, declaration, visited, violations);
            }
        } else if (type instanceof GenericArrayType array) {
            check(array.getGenericComponentType(), declaration, visited, violations);
        } else if (type instanceof TypeVariable<?> variable) {
            for (Type bound : variable.getBounds()) {
                check(bound, declaration, visited, violations);
            }
        } else if (type instanceof WildcardType wildcard) {
            for (Type bound : wildcard.getUpperBounds()) {
                check(bound, declaration, visited, violations);
            }
            for (Type bound : wildcard.getLowerBounds()) {
                check(bound, declaration, visited, violations);
            }
        }
    }

    private static boolean isVisible(Class<?> type) {
        return isVisible(type.getModifiers())
                && (type.getEnclosingClass() == null || isVisible(type.getEnclosingClass()));
    }

    private static boolean isVisible(int modifiers) {
        return Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers);
    }

    private static boolean isInternal(String name) {
        return name.startsWith(BASE_PACKAGE + "runtime.") || name.startsWith(BASE_PACKAGE + "deployment.");
    }
}
