plugins {
    alias(libs.plugins.quarkus.application)
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(project(":runtime"))
    implementation(project(":integration-tests:common"))
    implementation(libs.quarkus.config.yaml)
    implementation(libs.quarkus.jdbc.h2)
    implementation(libs.quarkus.rest.jackson)
    implementation(libs.quarkus.oidc)
    implementation(libs.quarkus.security)
    implementation(libs.quarkus.elytron.security.common)
    implementation(libs.quarkus.agroal)

    testImplementation(project(path = ":integration-tests:common", configuration = "testArtifacts"))
    testImplementation(libs.quarkus.junit5)
    testImplementation(libs.rest.assured)
    testRuntimeOnly(libs.junit.platform.launcher)
}

// Packaged/native tests must match the build-time profile of the artifact under test.
val verificationProfile = providers.systemProperty("quarkus.profile").orElse("prod")
tasks.named<Test>("quarkusIntTest") {
    when (verificationProfile.get()) {
        "multiple-issuers" -> include("**/multipleissuers/*IT.class")
        "reference-registration" -> include("**/ReferenceRegistrationIT.class")
        else -> {
            exclude("**/multipleissuers/**")
            exclude("**/ReferenceRegistrationIT.class")
        }
    }
}
