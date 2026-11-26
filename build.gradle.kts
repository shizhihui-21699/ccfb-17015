plugins {
    kotlin("jvm") version "2.2.21"
    application
}

group = "io.bms.knxsecure"
version = "1.0.0"

repositories {
    mavenCentral()
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        freeCompilerArgs.add("-Xjvm-default=all")
    }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("io.bms.knxsecure.demo.DemoMainKt")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    maxHeapSize = "1g"
}

tasks.register<JavaExec>("demo") {
    description = "Runs the attack/defence demonstration scenarios."
    group = "application"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.bms.knxsecure.demo.DemoMainKt")
    standardInput = System.`in`
}
