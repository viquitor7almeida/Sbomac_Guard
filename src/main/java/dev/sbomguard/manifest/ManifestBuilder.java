package dev.sbomguard.manifest;

import dev.sbomguard.crypto.HashService;
import dev.sbomguard.scanner.Component;
import dev.sbomguard.scanner.ProjectScanner.ScanResult;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import dev.sbomguard.scanner.Component.ComponentType;

public final class ManifestBuilder {

    public static final int SCHEMA_VERSION = 1;

    public Manifest build(ScanResult scan, Path sbomArquivo, Manifest.Tool tool) throws IOException {
        Component subjectComponent = scan.subject().orElse(null);

        Manifest.Subject subject = null;
        if (subjectComponent != null) {
            Path pomPath = scan.root().resolve(subjectComponent.path());
            subject = new Manifest.Subject(
                    subjectComponent.groupId(),
                    subjectComponent.name(),
                    subjectComponent.version(),
                    subjectComponent.purl(),
                    subjectComponent.path().toString(),
                    HashService.sha256Hex(pomPath));
        }

        List<ManifestComponent> components = new ArrayList<>();
        for (Component c : scan.components()) {
            if (c.equals(subjectComponent)) {
                continue;
            }
            components.add(toManifestComponent(c, scan));
        }

        return new Manifest(
                SCHEMA_VERSION,
                Instant.now().toString(),
                tool,
                subject,
                new Manifest.SbomRef(sbomArquivo.getFileName().toString(), HashService.sha256Hex(sbomArquivo)),
                List.copyOf(components));
    }

    private ManifestComponent toManifestComponent(Component c, ScanResult scan) throws IOException {
        String sha256 = null;
        if (c.type() == ComponentType.PROJECT_POM || c.type() == ComponentType.FILE_ARTIFACT) {
            sha256 = HashService.sha256Hex(scan.root().resolve(c.path()));
        }
        return new ManifestComponent(
                typeName(c.type()),
                c.groupId(),
                c.name(),
                c.version(),
                c.scope(),
                c.purl(),
                c.path() == null ? null : c.path().toString(),
                sha256);
    }

    private String typeName(ComponentType type) {
        return switch (type) {
            case PROJECT_POM -> ManifestComponent.TYPE_PROJECT_POM;
            case MAVEN_DEPENDENCY -> ManifestComponent.TYPE_MAVEN_DEPENDENCY;
            case FILE_ARTIFACT -> ManifestComponent.TYPE_FILE_ARTIFACT;
        };
    }
}
