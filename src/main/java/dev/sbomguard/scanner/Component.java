package dev.sbomguard.scanner;

import java.nio.file.Path;

public record Component(
        ComponentType type,
        String groupId,
        String name,
        String version,
        String scope,
        String purl,
        Path path) {

    public enum ComponentType {

        PROJECT_POM,

        MAVEN_DEPENDENCY,

        FILE_ARTIFACT
    }
}
