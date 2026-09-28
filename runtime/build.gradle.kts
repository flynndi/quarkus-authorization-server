plugins {
    alias(libs.plugins.quarkus.extension)
    alias(libs.plugins.maven.publish)
}

base {
    archivesName.set("quarkus-authorization-server")
}

quarkusExtension {
    deploymentModule.set("deployment")
}

dependencies {
    implementation(platform(libs.quarkus.bom))
    implementation(libs.quarkus.agroal)
    implementation(libs.jose4j)
    implementation(libs.quarkus.arc)
    implementation(libs.quarkus.jackson)
    implementation(libs.quarkus.security)
    implementation(libs.quarkus.vertx.http)
    implementation(libs.quarkus.smallrye.jwt.build)
    implementation(libs.quarkus.elytron.security.common)

    testImplementation(libs.junit.jupiter)
    testImplementation(libs.h2)
    testRuntimeOnly(libs.junit.platform.launcher)
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
        name.set("Quarkus Authorization Server")
        description.set("Quarkus extension runtime for authorization server support.")
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
