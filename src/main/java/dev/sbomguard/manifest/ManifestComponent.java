package dev.sbomguard.manifest;

public record ManifestComponent(
        String type,
        String group,
        String name,
        String version,
        String scope,
        String purl,
        String path,
        String sha256) {

    public static final String TYPE_PROJECT_POM = "project-pom";
    public static final String TYPE_MAVEN_DEPENDENCY = "maven-dependency";
    public static final String TYPE_FILE_ARTIFACT = "file-artifact";
}
