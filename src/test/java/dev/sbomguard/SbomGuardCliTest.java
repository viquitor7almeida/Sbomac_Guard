package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomGuardCliTest {

    private StringWriter stdout;
    private StringWriter stderr;

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @Test
    void helpImprimeUsageESaiComZero() {
        int exit = newCli().execute("--help");

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("Usage: sbomguard"),
                "esperava usage em stdout; obtido: " + stdout);
        assertEquals("", stderr.toString());
    }

    @Test
    void versaoImprimeVersaoSaiComZero() {
        int exit = newCli().execute("--version");

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("0.1.0-SNAPSHOT"));
    }

    @Test
    void argumentoInvalidoSaiComCodigoDoContrato() {
        int exit = newCli().execute("--opcao-que-nao-existe");

        assertEquals(ExitCodes.INVALID_ARGUMENT, exit);
        assertTrue(stderr.toString().contains("Usage: sbomguard"),
                "erro de uso deve ir para stderr com ajuda");
        assertEquals("", stdout.toString());
    }

    @Test
    void semArgumentosImprimeAjudaSaiComZero() {
        int exit = newCli().execute();

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("Usage: sbomguard"));
    }

    @Test
    void contratoDeExitCodesEhEstavel() {
        assertEquals(0, ExitCodes.OK);
        assertEquals(1, ExitCodes.GENERIC_ERROR);
        assertEquals(2, ExitCodes.INVALID_ARGUMENT);
        assertEquals(10, ExitCodes.INTEGRITY_VIOLATION);
        assertEquals(11, ExitCodes.SIGNATURE_INVALID);
        assertEquals(12, ExitCodes.UNEXPECTED_DEPENDENCY);
        assertEquals(13, ExitCodes.MANIFEST_NOT_FOUND);
    }
}
