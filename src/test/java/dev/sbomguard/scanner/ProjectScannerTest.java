package dev.sbomguard.scanner;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import dev.sbomguard.scanner.Component.ComponentType;

class ProjectScannerTest {

    private Path fixture(String nome) {
        return dev.sbomguard.testkit.Fixtures.path(nome);
    }

    @Test
    void miniProjetoCompletoComJarEExclusaoDeTarget() throws IOException {
        ProjectScanner.ScanResult result = new ProjectScanner().scan(fixture("mini-projeto"));

        assertTrue(result.pomFound());
        assertEquals(6, result.components().size(), "1 pom + 4 deps + 1 jar (war de target/ excluído)");

        Component projeto = result.components().get(0);
        assertEquals(ComponentType.PROJECT_POM, projeto.type());
        assertEquals(Path.of("pom.xml"), projeto.path(), "path do pom deve ser relativo à raiz");

        Component jar = result.components().stream()
                .filter(c -> c.type() == ComponentType.FILE_ARTIFACT)
                .findFirst().orElseThrow();
        assertEquals(Path.of("lib/fake-lib.jar"), jar.path());
        assertEquals("fake-lib.jar", jar.name());
        assertNull(jar.purl(), "arquivo não tem purl — não inventamos");

        assertTrue(result.components().stream().noneMatch(c -> c.path() != null && c.path().toString().contains("target")),
                "nada de target/ pode vazar para o inventário");
    }

    @Test
    void multiModuloDeduplicaDependenciasPorPurl() throws IOException {
        ProjectScanner.ScanResult result = new ProjectScanner().scan(fixture("multi-modulo"));

        long poms = result.components().stream().filter(c -> c.type() == ComponentType.PROJECT_POM).count();
        long picocli = result.components().stream()
                .filter(c -> c.type() == ComponentType.MAVEN_DEPENDENCY && "picocli".equals(c.name()))
                .count();

        assertEquals(3, poms);
        assertEquals(1, picocli, "picocli declarado em 3 poms deve virar 1 componente");
        assertEquals(5, result.components().size(), "3 poms + picocli + jackson");
    }

    @Test
    void semPomNaoEhErro() throws IOException {
        ProjectScanner.ScanResult result = new ProjectScanner().scan(fixture("sem-pom"));

        assertFalse(result.pomFound());
        assertEquals(1, result.components().size());
        assertEquals(ComponentType.FILE_ARTIFACT, result.components().get(0).type());
    }

    @Test
    void caminhosDosComponentesSaoRelativos() throws IOException {
        ProjectScanner.ScanResult result = new ProjectScanner().scan(fixture("mini-projeto"));

        for (Component c : result.components()) {
            if (c.path() != null) {
                assertFalse(c.path().isAbsolute(), "caminho absoluto vaza máquina no manifesto: " + c.path());
            }
        }
    }

    @Test
    void pomMalformadoEhPuladoEReportadoSemAbortar() throws IOException {
        ProjectScanner.ScanResult result = new ProjectScanner().scan(fixture("pom-quebrado"));

        assertFalse(result.pomFound());
        assertEquals(1, result.pomErrors().size());
        assertTrue(result.pomErrors().get(0).contains("malformado"));
        assertTrue(result.components().isEmpty());
    }
}
