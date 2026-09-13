package dev.sbomguard;

import dev.sbomguard.cli.ExitCodes;
import dev.sbomguard.crypto.KeyService;
import dev.sbomguard.testkit.Fixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LedgerCommandTest {

    @TempDir
    Path tempDir;

    private Path projeto;
    private Path manifesto;
    private Path ledger;
    private Path chavePublica;

    private StringWriter stdout;
    private StringWriter stderr;

    private CommandLine newCli() {
        stdout = new StringWriter();
        stderr = new StringWriter();
        return SbomGuardCli.configuredCommandLine()
                .setOut(new PrintWriter(stdout, true))
                .setErr(new PrintWriter(stderr, true));
    }

    @BeforeEach
    void preparaProjetoAtestadoAssinadoELedger() throws IOException {
        KeyService.GeneratedKeys chaves = new KeyService().generateAndSave(tempDir.resolve("keys"));
        chavePublica = chaves.publicKeyFile();

        projeto = Fixtures.copy("mini-projeto", tempDir);
        assertEquals(ExitCodes.OK, newCli().execute("attest", projeto.toString()));
        manifesto = projeto.resolve("sbomguard.manifest.json");
        assertEquals(ExitCodes.OK, newCli().execute("sign", manifesto.toString(),
                "--key", chaves.privateKeyFile().toString()));
        ledger = projeto.resolve("sbomguard.ledger.jsonl");
    }

    @Test
    void ledgerListaEntradasComIdentidade() throws IOException {
        int exit = newCli().execute("ledger", projeto.toString());

        assertEquals(ExitCodes.OK, exit);
        String out = stdout.toString();
        assertTrue(out.contains("#1"), out);
        assertTrue(out.contains("chave "), "entrada lista o fingerprint de quem assinou");
        assertTrue(out.contains("com.exemplo.demo:app:1.2.3"), "e o sujeito do atestado");
    }

    @Test
    void ledgerVerifyCadeiaIntactaSaiComZero() {
        int exit = newCli().execute("ledger", ledger.toString(), "--verify");

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("cadeia íntegra"));
        assertTrue(stdout.toString().contains("gênese e3b0c44298fc"));
    }

    @Test
    void ledgerAdulteradoVerifySaiComDez() throws IOException {
        adulterarPrimeiraEntrada();

        int exit = newCli().execute("ledger", ledger.toString(), "--verify");

        assertEquals(ExitCodes.INTEGRITY_VIOLATION, exit, "gate: ledger adulterado → 10");
        assertTrue(stderr.toString().contains("recalculado"));
    }

    @Test
    void signRecusaAnexarSobreLedgerAdulterado() throws IOException {
        adulterarPrimeiraEntrada();

        int exit = newCli().execute("sign", manifesto.toString(), "--key",
                tempDir.resolve("keys/sbomguard-signing.pem").toString());

        assertEquals(ExitCodes.GENERIC_ERROR, exit, "fail-closed: não se estende cadeia quebrada");
        assertTrue(stderr.toString().contains("recusa em anexar"));
    }

    @Test
    void ledgerInexistenteVerifySaiZeroExpondoALimitacao() {
        int exit = newCli().execute("ledger", tempDir.resolve("vazio").toString(), "--verify");

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("deleção total é indetectável"));
    }

    @Test
    void ledgerSemArgumentosUsaDiretorioAtual() throws IOException {
        String cwd = System.getProperty("user.dir");

        int exit = newCli().execute("ledger");

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("ledger"), cwd + " — default é o diretório atual");
    }

    private void adulterarPrimeiraEntrada() throws IOException {
        java.util.List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        linhas.set(0, linhas.get(0).replace("com.exemplo.demo", "evil.corp"));
        Files.write(ledger, linhas, StandardCharsets.UTF_8);
    }

    @Test
    void anchoredVerifyConformeSaiComZero() throws IOException {
        assertEquals(ExitCodes.OK, newCli().execute("anchor", projeto.toString(),
                "--key", tempDir.resolve("keys/sbomguard-signing.pem").toString()));

        int exit = newCli().execute("ledger", projeto.toString(), "--verify",
                "--anchor", projeto.resolve("sbomguard.anchor.json").toString(),
                "--key", chavePublica.toString());

        assertEquals(ExitCodes.OK, exit);
        assertTrue(stdout.toString().contains("conforme a âncora"));
    }

    @Test
    void anchoredVerifyPegaReescritaTotalQueACadeiaSozinhaNaoVe() throws Exception {
        assertEquals(ExitCodes.OK, newCli().execute("anchor", projeto.toString(),
                "--key", tempDir.resolve("keys/sbomguard-signing.pem").toString()));
        Path ancora = projeto.resolve("sbomguard.anchor.json");

        java.util.List<dev.sbomguard.ledger.LedgerEntry> originais =
                new dev.sbomguard.ledger.LedgerService().readAll(ledger);
        StringBuilder falsario = new StringBuilder();
        String prev = dev.sbomguard.ledger.LedgerService.GENESIS;
        int indice = 1;
        for (dev.sbomguard.ledger.LedgerEntry original : originais) {
            dev.sbomguard.ledger.LedgerEntry adulterada = new dev.sbomguard.ledger.LedgerEntry(
                    indice, original.created(), original.keyId(), "evil.corp:falso:9.9",
                    original.manifestSha256(), prev, null);
            String hash = dev.sbomguard.crypto.HashService.sha256Hex(
                    adulterada.canonicalJson().getBytes(StandardCharsets.UTF_8));
            falsario.append(new dev.sbomguard.ledger.LedgerEntry(indice, adulterada.created(),
                    adulterada.keyId(), adulterada.subject(), adulterada.manifestSha256(), prev, hash)
                    .toJsonLine()).append(System.lineSeparator());
            prev = hash;
            indice++;
        }
        Files.writeString(ledger, falsario.toString());

        int soCadeia = newCli().execute("ledger", projeto.toString(), "--verify");
        assertEquals(ExitCodes.OK, soCadeia, "cadeia sozinha segue cega à reescrita (limitação F8)");

        int comAncora = newCli().execute("ledger", projeto.toString(), "--verify",
                "--anchor", ancora.toString(), "--key", chavePublica.toString());
        assertEquals(ExitCodes.INTEGRITY_VIOLATION, comAncora,
                "a âncora externa contradita o falsário — a limitação ganhou contraditório");
        assertTrue(stderr.toString().contains("head do ledger diverge"));
    }

    @Test
    void anchoredVerifyAncoraAdulteradaSaiComOnze() throws IOException {
        assertEquals(ExitCodes.OK, newCli().execute("anchor", projeto.toString(),
                "--key", tempDir.resolve("keys/sbomguard-signing.pem").toString()));
        Path ancora = projeto.resolve("sbomguard.anchor.json");
        Files.writeString(ancora, Files.readString(ancora).replace("\"entryCount\":1", "\"entryCount\":99"));

        int exit = newCli().execute("ledger", projeto.toString(), "--verify",
                "--anchor", ancora.toString(), "--key", chavePublica.toString());

        assertEquals(ExitCodes.SIGNATURE_INVALID, exit, "âncora adulterada = autenticidade quebrada: 11");
        assertTrue(stderr.toString().contains("assinatura da âncora inválida"));
    }

    @Test
    void anchorExigeChavePublicaSaiComDois() throws IOException {
        assertEquals(ExitCodes.OK, newCli().execute("anchor", projeto.toString(),
                "--key", tempDir.resolve("keys/sbomguard-signing.pem").toString()));

        int exit = newCli().execute("ledger", projeto.toString(), "--verify",
                "--anchor", projeto.resolve("sbomguard.anchor.json").toString());

        assertEquals(ExitCodes.INVALID_ARGUMENT, exit, "contrato: 2 = argumento inválido");
    }

    @Test
    void anchoredVerifyLedgerDeletadoSaiComDez() throws IOException {
        assertEquals(ExitCodes.OK, newCli().execute("anchor", projeto.toString(),
                "--key", tempDir.resolve("keys/sbomguard-signing.pem").toString()));
        Files.delete(ledger);

        int exit = newCli().execute("ledger", projeto.toString(), "--verify",
                "--anchor", projeto.resolve("sbomguard.anchor.json").toString(),
                "--key", chavePublica.toString());

        assertEquals(ExitCodes.INTEGRITY_VIOLATION, exit, "a âncora atesta existência: deletar tudo não mais escapa");
        assertTrue(stderr.toString().contains("deleção total"));
    }
}
