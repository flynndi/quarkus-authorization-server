plugins {
    alias(libs.plugins.quarkus.application)
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(project(":runtime"))
    implementation(libs.quarkus.config.yaml)
    implementation(libs.quarkus.jdbc.h2)
    implementation(libs.quarkus.agroal)
    implementation(libs.quarkus.rest.jackson)
    implementation(libs.quarkus.oidc)
    implementation(libs.quarkus.security)
    implementation(libs.quarkus.elytron.security.common)

    testImplementation(libs.quarkus.junit5)
    testImplementation(libs.rest.assured)
    testRuntimeOnly(libs.junit.platform.launcher)
}
