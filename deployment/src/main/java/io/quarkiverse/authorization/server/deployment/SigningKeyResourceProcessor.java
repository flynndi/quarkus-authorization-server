package io.quarkiverse.authorization.server.deployment;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import jakarta.enterprise.inject.Default;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.ClassType;
import org.jboss.jandex.DotName;

import io.quarkiverse.authorization.server.runtime.token.ConfiguredAuthorizationServerKeySource;
import io.quarkiverse.authorization.server.token.AuthorizationServerKeySource;
import io.quarkus.arc.deployment.SynthesisFinishedBuildItem;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.runtime.util.StringUtil;
import io.smallrye.config.NameIterator;
import io.smallrye.config.SmallRyeConfig;

/** Bundles build-visible classpath keys without changing the runtime key-loading contract. */
@BuildSteps(onlyIf = AuthorizationServerProcessor.IsEnabled.class)
class SigningKeyResourceProcessor {
    private static final String SIGNING_PREFIX = "quarkus.authorization-server.signing.";
    private static final String CLASSPATH_PREFIX = "classpath:";

    @BuildStep
    void registerResources(AuthorizationServerBuildTimeConfig config, SynthesisFinishedBuildItem beans,
            BuildProducer<NativeImageResourceBuildItem> resources) {
        if (config.multipleIssuersAllowed()) {
            return;
        }
        var resolver = beans.getBeanResolver();
        var source = resolver.resolveAmbiguity(resolver.resolveBeans(
                ClassType.create(DotName.createSimple(AuthorizationServerKeySource.class)),
                AnnotationInstance.create(DotName.createSimple(Default.class), null, List.of())));
        // Respect CDI replacement, including producer methods and synthetic beans.
        if (source == null
                || !source.getBeanClass().equals(DotName.createSimple(ConfiguredAuthorizationServerKeySource.class))) {
            return;
        }
        Set<String> locations = SigningKeyResourceProcessor.classpathResources(
                ConfigProvider.getConfig().unwrap(SmallRyeConfig.class));
        if (!locations.isEmpty()) {
            resources.produce(new NativeImageResourceBuildItem(List.copyOf(locations)));
        }
    }

    static Set<String> classpathResources(SmallRyeConfig config) {
        // Fixed names must also resolve from environment variables, whose enumerated names are lossy.
        Set<String> properties = new TreeSet<>(List.of(SIGNING_PREFIX + "private-key-location",
                SIGNING_PREFIX + "public-key-location"));
        for (String property : config.getPropertyNames()) {
            if (SigningKeyResourceProcessor.isKeyLocation(property)) {
                properties.add(property);
            }
        }
        Set<String> resources = new TreeSet<>();
        for (String property : properties) {
            var value = config.getConfigValue(property);
            // An expression may only become resolvable at runtime, for example a secret mount path.
            if (value.hasProblems() || value.getValue() == null || !value.getValue().startsWith(CLASSPATH_PREFIX)) {
                continue;
            }
            String resource = StringUtil.changePrefix(value.getValue().substring(CLASSPATH_PREFIX.length()), "/", "");
            if (!resource.isEmpty()) {
                resources.add(resource);
            }
        }
        return resources;
    }

    private static boolean isKeyLocation(String property) {
        if (!property.startsWith(SIGNING_PREFIX)) {
            return false;
        }
        // Use SmallRye's property-name parser so quoted key IDs can contain dots.
        var name = new NameIterator(property.substring(SIGNING_PREFIX.length()));
        if (name.nextSegmentEquals("keys")) {
            name.next();
            if (!name.hasNext()) {
                return false;
            }
            name.next();
        }
        if (!name.hasNext()) {
            return false;
        }
        boolean location = name.nextSegmentEquals("private-key-location") || name.nextSegmentEquals("public-key-location");
        name.next();
        return location && !name.hasNext();
    }
}
