package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.KeyService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class KeygenCommandTest {

    @TempDir
    Path tempDir;

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
    void keygenGeraParComFingerprintExibido() throws Exception {
        int exit = newCli().execute("keygen", "--out-dir", tempDir.toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(Files.isRegularFile(tempDir.resolve(KeyService.PRIVATE_KEY_FILE)));
        assertTrue(Files.isRegularFile(tempDir.resolve(KeyService.PUBLIC_KEY_FILE)));
        assertTrue(java.util.regex.Pattern.compile("fingerprint:\\s+[0-9a-f]{64}")
                .matcher(stdout.toString()).find());
        assertTrue(stdout.toString().contains("NUNCA commitar"));
    }

    @Test
    void keygenCriaPermissaoRestrictivaNaPrivada() throws Exception {
        assumeTrue(Files.getFileStore(tempDir)
                .supportsFileAttributeView(PosixFileAttributeView.class), "filesystem sem POSIX");

        newCli().execute("keygen", "--out-dir", tempDir.toString());

        assertEquals("rw-------", PosixFilePermissions.toString(
                Files.getPosixFilePermissions(tempDir.resolve(KeyService.PRIVATE_KEY_FILE))));
    }

    @Test
    void keygenOutDirAninhadoEhCriado() {
        Path aninhado = tempDir.resolve("x/y");

        int exit = newCli().execute("keygen", "--out-dir", aninhado.toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(Files.isRegularFile(aninhado.resolve(KeyService.PUBLIC_KEY_FILE)));
    }
}
