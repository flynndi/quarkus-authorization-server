pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
        mavenLocal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        mavenLocal()
    }
}

rootProject.name = "quarkus-authorization-server"

include(
    "runtime",
    "deployment",
    "examples:authorization-code",
    "examples:client-credentials",
    "examples:device-authorization",
    "examples:password-grant",
    "integration-tests:common",
    "integration-tests:password-grant",
    "integration-tests:authorization-code",
    "integration-tests:client-credentials",
    "integration-tests:device-authorization",
    "integration-tests:token-exchange",
)
