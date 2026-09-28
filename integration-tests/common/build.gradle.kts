plugins {
    `java-library`
}

description = "Shared integration-test server fixtures and HTTP drivers"

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(project(":runtime"))
    implementation(libs.jose4j)
    implementation(libs.quarkus.smallrye.jwt.build)
    implementation(libs.quarkus.oidc)
    implementation(libs.quarkus.rest.jackson)
    implementation(libs.quarkus.elytron.security.common)

    testImplementation(libs.rest.assured)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Share the HTTP drivers without adding test libraries to the server JAR.
val testJar = tasks.register<Jar>("testJar") {
    archiveClassifier.set("tests")
    from(sourceSets.test.get().output)
}

val testArtifacts = configurations.create("testArtifacts") {
    isCanBeConsumed = true
    isCanBeResolved = false
    extendsFrom(configurations.testImplementation.get(), configurations.testRuntimeOnly.get())
}

artifacts {
    add(testArtifacts.name, testJar)
}

tasks.assemble {
    dependsOn(testJar)
}

tasks.test {
    // This module's test sources currently contain shared drivers, not executable tests.
    failOnNoDiscoveredTests = false
}
