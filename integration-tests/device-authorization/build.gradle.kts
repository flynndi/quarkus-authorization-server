plugins {
    alias(libs.plugins.quarkus.application)
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(project(":runtime"))
    implementation(project(":integration-tests:common"))
    implementation(libs.quarkus.config.yaml)
    implementation(libs.quarkus.jdbc.h2)
    implementation(libs.quarkus.oidc)
    implementation(libs.quarkus.rest.jackson)
    implementation(libs.quarkus.rest.qute)
    implementation(libs.quarkus.security)
    implementation(libs.quarkus.elytron.security.common)

    testImplementation(project(path = ":integration-tests:common", configuration = "testArtifacts"))
    testImplementation(libs.quarkus.junit5)
    testImplementation(libs.rest.assured)
    testRuntimeOnly(libs.junit.platform.launcher)
}
