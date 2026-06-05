// Kotlin build script — `.kts` extension. JVM family; spec layer treats as Java.
plugins {
    java
    application
}

application {
    mainClass.set("com.example.Main")
}
