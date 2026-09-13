package dev.sbomguard.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import dev.sbomguard.scanner.Component.ComponentType;

class MavenPomScannerTest {

    @TempDir
    Path tempDir;

    private Path fixture(String nome) {
        return dev.sbomguard.testkit.Fixtures.path(nome);
    }

    @Test
    void miniProjetoGeraProjetoEQuatroDependencias() {
        List<Component> components = new MavenPomScanner().scan(fixture("mini-projeto/pom.xml"));

        assertEquals(5, components.size());

        Component projeto = components.get(0);
        assertEquals(ComponentType.PROJECT_POM, projeto.type());
        assertEquals("com.exemplo.demo", projeto.groupId());
        assertEquals("app", projeto.name());
        assertEquals("1.2.3", projeto.version());
        assertEquals("pkg:maven/com.exemplo.demo/app@1.2.3", projeto.purl());

        Component picocli = components.get(1);
        assertEquals(ComponentType.MAVEN_DEPENDENCY, picocli.type());
        assertEquals("compile", picocli.scope(), "scope nulo deve normalizar para compile");
        assertEquals("pkg:maven/info.picocli/picocli@4.7.7", picocli.purl());
        assertNull(picocli.path(), "dependência declarada não tem path (limitação MVP)");

        Component junit = components.get(2);
        assertEquals("test", junit.scope());
        assertEquals("${junit.version}", junit.version(), "versão de propriedade fica crua");
    }

    @Test
    void herancaPreencheCoordenadasDoParent() {
        List<Component> components = new MavenPomScanner().scan(fixture("heranca/pom.xml"));

        Component projeto = components.get(0);
        assertEquals("com.exemplo.pais", projeto.groupId());
        assertEquals("filho", projeto.name());
        assertEquals("1.0.0", projeto.version());
        assertEquals("pkg:maven/com.exemplo.pais/filho@1.0.0", projeto.purl());
    }

    @Test
    void versaoDePropriedadeGeraPurlSemVersao() {
        List<Component> components = new MavenPomScanner().scan(fixture("mini-projeto/pom.xml"));

        Component junit = components.get(2);
        assertEquals("pkg:maven/org.junit.jupiter/junit-jupiter", junit.purl(),
                "placeholder não vira versão fabricada no purl");
    }

    @Test
    void pomMalformadoGeraScanException() {
        ScanException e = assertThrows(ScanException.class,
                () -> new MavenPomScanner().scan(fixture("pom-quebrado/pom.xml")));
        assertTrue(e.getMessage().contains("malformado"));
    }

    @Test
    void pomSemArtifactIdGeraScanException() {
        ScanException e = assertThrows(ScanException.class,
                () -> new MavenPomScanner().scan(fixture("pom-sem-artifactid/pom.xml")));
        assertTrue(e.getMessage().contains("artifactId"));
    }

    @Test
    void pomInexistenteGeraScanExceptionComCausaIo() {
        ScanException e = assertThrows(ScanException.class,
                () -> new MavenPomScanner().scan(tempDir.resolve("nao-existe/pom.xml")));
        assertTrue(e.getCause() instanceof NoSuchFileException);
    }
}
