package io.quarkiverse.authorization.server.deployment;

import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import io.quarkus.builder.BuildChainBuilder;
import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;

/** Verifies augmentation output without claiming to run a native executable. */
final class NativeImageResourceAssertions {
    static Consumer<BuildChainBuilder> verify(Set<String> included, Set<String> excluded) {
        return builder -> {
            builder.addBuildStep(context -> {
                Set<String> resources = context.consumeMulti(NativeImageResourceBuildItem.class).stream()
                        .flatMap(item -> item.getResources().stream()).collect(Collectors.toSet());
                if (!resources.containsAll(included) || excluded.stream().anyMatch(resources::contains)) {
                    throw new IllegalStateException("Unexpected native resource registrations: " + resources
                            + "; required: " + included + "; excluded: " + excluded);
                }
                context.produce(new ResourcesVerifiedBuildItem());
            }).consumes(NativeImageResourceBuildItem.class).produces(ResourcesVerifiedBuildItem.class).build();
            builder.addFinal(ResourcesVerifiedBuildItem.class);
        };
    }

    static final class ResourcesVerifiedBuildItem extends SimpleBuildItem {
    }
}
