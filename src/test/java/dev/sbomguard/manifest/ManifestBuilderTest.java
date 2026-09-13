package dev.sbomguard.manifest;

import dev.sbomguard.crypto.HashService;
import dev.sbomguard.scanner.ProjectScanner;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManifestBuilderTest {

    @TempDir
    Path tempDir;

    private final ManifestBuilder builder = new ManifestBuilder();
    private final Manifest.Tool tool = new Manifest.Tool("sbomguard", "teste");

    private Path sbomArquivoFake() throws IOException {
        Path sbom = tempDir.resolve("sbomguard.sbom.json");
        Files.writeString(sbom, "{\"bomFormat\":\"CycloneDX\"}");
        return sbom;
    }

    @Test
    void miniProjetoHasheiaSujeitoJarESbom() throws IOException {
        ProjectScanner.ScanResult scan = new ProjectScanner().scan(Fixtures.path("mini-projeto"));
        Path sbom = sbomArquivoFake();

        Manifest manifest = builder.build(scan, sbom, tool);

        assertEquals(ManifestBuilder.SCHEMA_VERSION, manifest.schemaVersion());
        assertEquals("sbomguard", manifest.tool().name());

        Manifest.Subject subject = manifest.subject();
        assertEquals("com.exemplo.demo", subject.group());
        assertEquals("app", subject.name());
        assertEquals(HashService.sha256Hex(scan.root().resolve("pom.xml")), subject.sha256(),
                "hash do pom do sujeito deve bater com o arquivo");
        assertEquals("pom.xml", subject.path());

        assertEquals(HashService.sha256Hex(sbom), manifest.sbom().sha256(), "âncora manifest↔SBOM");
        assertEquals("sbomguard.sbom.json", manifest.sbom().path().toString());

        assertEquals(5, manifest.components().size(), "4 deps (sem hash) + 1 jar (com hash)");
        Optional<ManifestComponent> jar = manifest.components().stream()
                .filter(c -> "fake-lib.jar".equals(c.name())).findFirst();
        assertTrue(jar.isPresent());
        assertEquals(HashService.sha256Hex(scan.root().resolve("lib/fake-lib.jar")), jar.get().sha256());

        Optional<ManifestComponent> picocli = manifest.components().stream()
                .filter(c -> "picocli".equals(c.name())).findFirst();
        assertTrue(picocli.isPresent());
        assertNull(picocli.get().sha256(), "dependência declarada: identidade sem hash");
    }

    @Test
    void versaoDePropriedadeFicaCruaNoManifesto() throws IOException {
        ProjectScanner.ScanResult scan = new ProjectScanner().scan(Fixtures.path("mini-projeto"));

        Manifest manifest = builder.build(scan, sbomArquivoFake(), tool);

        Optional<ManifestComponent> junit = manifest.components().stream()
                .filter(c -> "junit-jupiter".equals(c.name())).findFirst();
        assertTrue(junit.isPresent());
        assertEquals("${junit.version}", junit.get().version(),
                "manifesto registra estado DECLARADO cru (diferente do SBOM, que omite placeholder)");
    }

    @Test
    void multiModuloHasheiaPomsDeModulos() throws IOException {
        ProjectScanner.ScanResult scan = new ProjectScanner().scan(Fixtures.path("multi-modulo"));

        Manifest manifest = builder.build(scan, sbomArquivoFake(), tool);

        assertEquals("multi", manifest.subject().name(), "sujeito é o pom raiz");
        assertEquals(4, manifest.components().size(), "2 poms de módulo (com hash) + 2 deps (sem hash)");
        ManifestComponent modA = manifest.components().stream()
                .filter(c -> "mod-a".equals(c.name())).findFirst().orElseThrow();
        assertEquals(ManifestComponent.TYPE_PROJECT_POM, modA.type());
        assertNotNull(modA.sha256());
        assertEquals(HashService.sha256Hex(scan.root().resolve("mod-a/pom.xml")), modA.sha256());
    }

    @Test
    void semPomGeraManifestoSemSujeito() throws IOException {
        ProjectScanner.ScanResult scan = new ProjectScanner().scan(Fixtures.path("sem-pom"));

        Manifest manifest = builder.build(scan, sbomArquivoFake(), tool);

        assertNull(manifest.subject());
        assertEquals(1, manifest.components().size());
        assertNotNull(manifest.components().get(0).sha256(), "jar é hasheado mesmo sem pom");
    }
}
