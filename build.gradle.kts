import org.apache.tools.ant.util.Base64Converter
import org.jetbrains.kotlin.utils.addToStdlib.cast
import org.jetbrains.kotlin.utils.addToStdlib.castAll

plugins {
    kotlin("multiplatform") version "1.8.21"
    id("dev.petuska.npm.publish") version "3.3.1"
    id("org.jetbrains.kotlin.plugin.serialization") version "1.8.21"
    `maven-publish`
}

group = "id.walt"
version = "1.SNAPSHOT"

repositories {
    mavenCentral()
    maven("https://maven.walt.id/repository/waltid-ssi-kit/")
}

kotlin {
    jvm {
        jvmToolchain(16)
        withJava()
        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    js(IR) {
        browser {
            commonWebpackConfig {
                cssSupport {
                    enabled.set(true)
                }
            }
        }
        nodejs() {
            generateTypeScriptDefinitions()
        }
        binaries.library()
    }
    val hostOs = System.getProperty("os.name")
    val isMingwX64 = hostOs.startsWith("Windows")
    val nativeTarget = when {
        hostOs == "Mac OS X" -> macosX64("native")
        hostOs == "Linux" -> linuxX64("native")
        isMingwX64 -> mingwX64("native")
        else -> throw GradleException("Host OS is not supported in Kotlin/Native.")
    }
    val kryptoVersion = "4.0.1"
    val ktor_version = "2.3.3"


    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.4.1")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-properties:1.4.1")
                implementation("com.soywiz.korlibs.krypto:krypto:$kryptoVersion")
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.1")
                implementation("io.ktor:ktor-http:$ktor_version")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.0")
                implementation("id.walt:waltid-sd-jwt:1.2306191408.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation("io.kotest:kotest-assertions-core:5.5.5")

                implementation("io.kotest:kotest-assertions-json:5.5.5")
            }
        }
        val jvmMain by getting {
            dependencies {
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation("io.mockk:mockk:1.13.2")

                implementation("io.kotest:kotest-runner-junit5:5.5.5")
                implementation("io.kotest:kotest-assertions-core:5.5.5")
                implementation("io.kotest:kotest-assertions-json:5.5.5")

                implementation("com.nimbusds:oauth2-oidc-sdk:10.7")

                implementation("io.ktor:ktor-server-core-jvm:$ktor_version")
                implementation("io.ktor:ktor-server-netty-jvm:$ktor_version")
                implementation("io.ktor:ktor-server-status-pages-jvm:$ktor_version")
                implementation("io.ktor:ktor-server-default-headers-jvm:$ktor_version")
                implementation("io.ktor:ktor-server-content-negotiation:$ktor_version")
                implementation("io.ktor:ktor-client-core:$ktor_version")
                implementation("io.ktor:ktor-client-cio:$ktor_version")
                implementation("io.ktor:ktor-client-content-negotiation:$ktor_version")
                implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor_version")
            }
        }
        val jsMain by getting {
            dependencies {
                implementation(npm("jose", "~4.14.4"))
            }
        }
        val jsTest by getting {

        }
        val nativeMain by getting
        val nativeTest by getting
    }

    publishing {
        repositories {
            val envUsername = System.getenv("MAVEN_USERNAME")
            val envPassword = System.getenv("MAVEN_PASSWORD")
            val usernameFile = File("secret_maven_username.txt")
            val passwordFile = File("secret_maven_password.txt")
            val secretMavenUsername = envUsername ?: usernameFile.let { if (it.isFile) it.readLines().first() else "" }
            val secretMavenPassword = envPassword ?: passwordFile.let { if (it.isFile) it.readLines().first() else "" }
            val hasMavenAuth = secretMavenUsername.isNotEmpty() && secretMavenPassword.isNotEmpty()
            if(hasMavenAuth) {
                maven {
                    url = uri("https://maven.walt.id/repository/waltid-ssi-kit/")
                    credentials {
                        username = secretMavenUsername
                        password = secretMavenPassword
                    }
                }
            }
        }
    }
}

npmPublish {
    registries {
        val envToken = System.getenv("NPM_TOKEN")
        val npmTokenFile = File("secret_npm_token.txt")
        val secretNpmToken = envToken ?: npmTokenFile.let { if (it.isFile) it.readLines().first() else "" }
        val hasNPMToken = secretNpmToken.isNotEmpty()
        val isReleaseBuild = Regex("\\d+.\\d+.\\d+").matches(version.get())
        println("NPM token: ${hasNPMToken}")
        println("Release build: ${isReleaseBuild}")
        if(isReleaseBuild && hasNPMToken) {
            readme.set(File("README.md"))
            register("npmjs") {
                uri.set(uri("https://registry.npmjs.org"))
                authToken.set(secretNpmToken)
            }
        }
    }
}
