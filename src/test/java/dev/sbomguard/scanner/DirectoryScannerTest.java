package dev.sbomguard.scanner;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectoryScannerTest {

    @TempDir
    Path tempDir;

    @Test
    void coletaPomsEArtefatosRespeitandoExclusoes() throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>");
        Files.createDirectories(tempDir.resolve("lib"));
        Files.createFile(tempDir.resolve("lib/x.jar"));
        Files.createDirectories(tempDir.resolve("target"));
        Files.createFile(tempDir.resolve("target/build.war"));
        Files.createDirectories(tempDir.resolve(".git"));
        Files.createFile(tempDir.resolve(".git/config"));
        Files.createDirectories(tempDir.resolve("sub"));
        Files.createFile(tempDir.resolve("sub/y.jar"));
        Files.writeString(tempDir.resolve("sub/leia-me.txt"), "não é artefato");

        DirectoryScanner.DirectoryScan result = new DirectoryScanner().scan(tempDir);

        assertEquals(List.of(tempDir.resolve("pom.xml")), result.pomFiles());
        assertEquals(List.of(tempDir.resolve("lib/x.jar"), tempDir.resolve("sub/y.jar")),
                result.artifactFiles());
        assertTrue(result.skippedSymlinks().isEmpty());
    }

    @Test
    void symlinkParaArquivoEDiretorioSaoPuladosEReportados() throws IOException {
        Files.createFile(tempDir.resolve("real.jar"));
        Files.createDirectories(tempDir.resolve("dir-real"));
        try {
            Files.createSymbolicLink(tempDir.resolve("link.jar"), tempDir.resolve("real.jar"));
            Files.createSymbolicLink(tempDir.resolve("dir-link"), tempDir.resolve("dir-real"));
        } catch (IOException | UnsupportedOperationException e) {
            Assumptions.abort("filesystem sem suporte a symlink: " + e.getMessage());
        }

        DirectoryScanner.DirectoryScan result = new DirectoryScanner().scan(tempDir);

        assertEquals(List.of(tempDir.resolve("real.jar")), result.artifactFiles(),
                "symlink não pode virar artefato");
        assertEquals(2, result.skippedSymlinks().size(),
                "link de arquivo e link de direttoreo devem ser reportados");
        assertTrue(result.skippedSymlinks().contains(tempDir.resolve("link.jar")));
        assertTrue(result.skippedSymlinks().contains(tempDir.resolve("dir-link")));
    }

    @Test
    void ordemEDeterministicaEntreExecucoes() throws IOException {
        Files.createDirectories(tempDir.resolve("z"));
        Files.createDirectories(tempDir.resolve("a"));
        Files.createFile(tempDir.resolve("z/ultimo.jar"));
        Files.createFile(tempDir.resolve("a/primeiro.jar"));
        Files.createFile(tempDir.resolve("meio.jar"));

        DirectoryScanner.DirectoryScan r1 = new DirectoryScanner().scan(tempDir);
        DirectoryScanner.DirectoryScan r2 = new DirectoryScanner().scan(tempDir);

        assertEquals(r1.artifactFiles(), r2.artifactFiles());
        assertEquals(List.of(tempDir.resolve("a/primeiro.jar"), tempDir.resolve("meio.jar"),
                tempDir.resolve("z/ultimo.jar")), r1.artifactFiles(), "ordem deve ser lexicográfica");
    }

    @Test
    void raizInexistenteLancaNoSuchFileException() {
        assertThrows(NoSuchFileException.class,
                () -> new DirectoryScanner().scan(tempDir.resolve("nao-existe")));
    }
}
