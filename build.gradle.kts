import com.diffplug.gradle.spotless.SpotlessExtension

plugins {
    alias(libs.plugins.quarkus.extension) apply false
    alias(libs.plugins.quarkus.application) apply false
    alias(libs.plugins.maven.publish) apply false
    alias(libs.plugins.spotless) apply false
}

val eclipseFormatterVersion = libs.versions.eclipse.formatter.get()

allprojects {
    group = providers.gradleProperty("GROUP_ID").get()
    version = providers.gradleProperty("VERSION").get()
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<SpotlessExtension> {
        java {
            // Include integrationTest sources without picking up Quarkus-generated build output.
            target("src/*/java/**/*.java")
            eclipse(eclipseFormatterVersion)
                .configFile(rootProject.file("gradle/formatting/eclipse-format.xml"))
            importOrder("java", "javax", "jakarta", "org", "com")
            removeUnusedImports()
            trimTrailingWhitespace()
            endWithNewline()
        }
    }

    extensions.configure<JavaPluginExtension> {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
        withSourcesJar()
    }

    val spotlessApply = tasks.named("spotlessApply")
    tasks.named("build") {
        dependsOn(spotlessApply)
    }
    // Order source consumers after formatting without making standalone check tasks rewrite sources.
    // Spotless already orders its check tasks after the corresponding apply tasks.
    tasks.withType<SourceTask>().configureEach {
        mustRunAfter(spotlessApply)
    }
    tasks.named("sourcesJar") {
        mustRunAfter(spotlessApply)
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.add("-parameters")
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}
