plugins {
    alias(libs.plugins.maven.publish)
}

base {
    archivesName.set("quarkus-authorization-server-deployment")
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(project(":runtime"))
    implementation(libs.quarkus.core.deployment)
    implementation(libs.quarkus.devui.deployment.spi)
    implementation(libs.quarkus.arc.deployment)
    implementation(libs.quarkus.jackson.deployment)
    implementation(libs.quarkus.security.deployment)
    implementation(libs.quarkus.vertx.http.deployment)
    implementation(libs.quarkus.smallrye.jwt.build.deployment)
    implementation(libs.quarkus.elytron.security.common.deployment)

    testImplementation(libs.quarkus.junit5.internal)
    // The extension test model uses TEST dependencies, so dev-mode tests need the Dev UI explicitly.
    testImplementation(libs.quarkus.devui.deployment)
    testImplementation(libs.quarkus.config.yaml)
    testImplementation(libs.quarkus.rest.jackson.deployment)
    testImplementation(libs.rest.assured)
}

sourceSets.named("test") {
    // QuarkusDevModeTest resolves src/test/java two levels above the test classes directory.
    java.destinationDirectory.set(layout.buildDirectory.dir("test-classes"))
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
    coordinates(
        project.group.toString(),
        base.archivesName.get(),
        project.version.toString(),
    )

    pom {
        name.set("OAuth2 and OpenID Connect Server Extension - Deployment (Experimental)")
        description.set("Build-time integration for the experimental, community-maintained OAuth2 and OpenID Connect Server Extension.")
        url.set("https://github.com/flynndi/quarkus-authorization-server")
        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("flynndi")
                name.set("flynndi")
                email.set("lixuan0520@gmail.com")
            }
        }
        scm {
            url.set("https://github.com/flynndi/quarkus-authorization-server")
            connection.set("scm:git:https://github.com/flynndi/quarkus-authorization-server.git")
            developerConnection.set("scm:git:ssh://git@github.com/flynndi/quarkus-authorization-server.git")
        }
    }
}
