package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanCommandTest {

    private StringWriter stdout;
    private StringWriter stderr;

    private Path fixture(String nome) {
        return dev.sbomguard.testkit.Fixtures.path(nome);
    }

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @Test
    void scanImprimeInventarioFormatado() {
        int exit = newCli().execute("scan", fixture("mini-projeto").toString());

        assertEquals(ExitCodes.OK, exit);
        String out = stdout.toString();
        assertTrue(out.contains("[pom] com.exemplo.demo:app:1.2.3  (pom.xml)"));
        assertTrue(out.contains("[dep] pkg:maven/info.picocli/picocli@4.7.7 (compile)"));
        assertTrue(out.contains("[dep] pkg:maven/org.junit.jupiter/junit-jupiter (test)"));
        assertTrue(out.contains("[jar] lib/fake-lib.jar"));
        assertTrue(out.contains("total: 6 componentes"));
        assertFalse(out.contains("target"), "exclusões não podem vazar na saída");
        assertEquals("", stderr.toString());
    }

    @Test
    void scanSemPomAvisaMasNaoFalha() {
        int exit = newCli().execute("scan", fixture("sem-pom").toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stderr.toString().contains("nenhum pom.xml"));
        assertTrue(stdout.toString().contains("[jar] solitario.jar"));
    }

    @Test
    void scanDiretorioInexistenteSaiComUm() {
        int exit = newCli().execute("scan", "/caminho/que/nao/existe");

        assertEquals(ExitCodes.GENERIC_ERROR, exit);
        assertTrue(stderr.toString().contains("não é um diretório"));
        assertEquals("", stdout.toString());
    }

    @Test
    void scanPomMalformadoEhAvisadoSemFalhar() {
        int exit = newCli().execute("scan", fixture("pom-quebrado").toString());

        assertEquals(ExitCodes.OK, exit, "scan é inventário: pom quebrado não aborta");
        assertTrue(stderr.toString().contains("malformado"));
        assertTrue(stdout.toString().contains("total: 0 componentes"));
        assertFalse(stderr.toString().contains("at dev.sbomguard"), "sem stacktrace vazeado");
    }
}
