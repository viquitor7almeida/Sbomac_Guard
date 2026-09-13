package dev.sbomguard.ledger;

import dev.sbomguard.crypto.HashService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AnchorServiceTest {

    @TempDir
    Path tempDir;

    private final AnchorService service = new AnchorService();
    private final LedgerService ledgerService = new LedgerService();
    private KeyPair par;

    @BeforeEach
    void geraChaves() throws NoSuchAlgorithmException {
        par = KeyPairGeneratorHolder.par();
    }

    private static final class KeyPairGeneratorHolder {
        static KeyPair par() throws NoSuchAlgorithmException {
            return java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        }
    }

    private Path ledgerComDuasEntradas() throws IOException {
        Path ledger = tempDir.resolve("ledger.jsonl");
        ledgerService.append(ledger, "chave-a", "g:a:1", "hash-1");
        ledgerService.append(ledger, "chave-a", "g:a:2", "hash-2");
        return ledger;
    }

    @Test
    void criaEVerificaAncoraConforme() throws IOException {
        Path ledger = ledgerComDuasEntradas();

        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");
        AnchorService.AnchorCheck check = service.verify(ledger,
                gravar(anchor), par.getPublic());

        assertEquals(2, anchor.entryCount());
        assertTrue(check.anchorSignatureValid());
        assertTrue(check.intact(), () -> "problemas: " + check.problems());
    }

    @Test
    void ancoraDeLedgerVazioAncoraAGenese() throws IOException {
        Path ledgerInexistente = tempDir.resolve("vazio.jsonl");

        Anchor anchor = service.create(ledgerInexistente, par.getPrivate(), "chave-a");

        assertEquals(0, anchor.entryCount());
        assertEquals(LedgerService.GENESIS, anchor.ledgerHead());
    }

    @Test
    void reescritaTotalEDetectadaComAncora() throws IOException {

        Path ledger = ledgerComDuasEntradas();
        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");

        falsificarCadeiaInteira(ledger);

        assertTrue(ledgerService.verifyChain(ledger).intact(),
                "a cadeia sozinha continua cega à reescrita (limitação conhecida)");
        AnchorService.AnchorCheck check = service.verify(ledger, gravar(anchor), par.getPublic());

        assertTrue(check.anchorSignatureValid(), "a âncora em si está íntegra");
        assertFalse(check.intact(), "mas o ledger local NÃO confere com o que foi publicado");
        assertTrue(check.problems().stream().anyMatch(p -> p.contains("head do ledger diverge")),
                () -> "problemas: " + check.problems());
    }

    @Test
    void truncamentoEDetectadoPelaContagem() throws IOException {
        Path ledger = tempDir.resolve("ledger.jsonl");
        ledgerService.append(ledger, "chave-a", "g:a:1", "hash-1");
        ledgerService.append(ledger, "chave-a", "g:a:2", "hash-2");
        ledgerService.append(ledger, "chave-a", "g:a:3", "hash-3");
        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");

        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        linhas.remove(linhas.size() - 1);
        Files.write(ledger, linhas, StandardCharsets.UTF_8);

        AnchorService.AnchorCheck check = service.verify(ledger, gravar(anchor), par.getPublic());

        assertFalse(check.intact());
        assertTrue(check.problems().stream().anyMatch(p -> p.contains("contagem diverge")),
                () -> "problemas: " + check.problems());
    }

    @Test
    void delecaoTotalDoLedgerEDetectadaPelaAncora() throws IOException {
        Path ledger = ledgerComDuasEntradas();
        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");

        Files.delete(ledger);

        AnchorService.AnchorCheck check = service.verify(ledger, gravar(anchor), par.getPublic());

        assertFalse(check.intact(), "deletar tudo deixou de ser caminho de fuga (era indetectável na F8)");
        assertTrue(check.problems().stream().anyMatch(p -> p.contains("deleção total")));
    }

    @Test
    void ancoraAdulteradaTemAssinaturaInvalida() throws IOException {
        Path ledger = ledgerComDuasEntradas();
        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");
        String adulterada = anchor.serialize().replace("\"entryCount\":2", "\"entryCount\":99");
        Path arquivo = gravarRaw(adulterada);

        AnchorService.AnchorCheck check = service.verify(ledger, arquivo, par.getPublic());

        assertFalse(check.anchorSignatureValid(), "mudar a contagem sem re-assinar quebra a assinatura");
    }

    @Test
    void ancoraDeOutraChaveNaoValida() throws Exception {
        Path ledger = ledgerComDuasEntradas();
        Anchor anchor = service.create(ledger, par.getPrivate(), "chave-a");
        KeyPair outroPar = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        AnchorService.AnchorCheck check = service.verify(ledger, gravar(anchor), outroPar.getPublic());

        assertFalse(check.anchorSignatureValid());
    }

    @Test
    void createRecusaLedgerComCadeiaQuebrada() throws IOException {
        Path ledger = ledgerComDuasEntradas();
        List<String> linhas = Files.readAllLines(ledger, StandardCharsets.UTF_8);
        Files.write(ledger, List.of(linhas.get(0).replace("g:a:1", "g:FALSO")),
                StandardCharsets.UTF_8);

        IOException e = assertThrows(IOException.class,
                () -> service.create(ledger, par.getPrivate(), "chave-a"));

        assertTrue(e.getMessage().contains("recusa em ancorar"));
    }

    private Path gravar(Anchor anchor) throws IOException {
        return gravarRaw(anchor.serialize());
    }

    private Path gravarRaw(String json) throws IOException {
        Path arquivo = tempDir.resolve("sbomguard.anchor.json");
        Files.writeString(arquivo, json);
        return arquivo;
    }

    private void falsificarCadeiaInteira(Path ledger) throws IOException {
        List<LedgerEntry> originais = ledgerService.readAll(ledger);
        StringBuilder falsario = new StringBuilder();
        String prev = LedgerService.GENESIS;
        int indice = 1;
        for (LedgerEntry original : originais) {
            LedgerEntry adulterada = new LedgerEntry(indice, original.created(), original.keyId(),
                    "evil.corp:falso:9.9", original.manifestSha256(), prev, null);
            String hash = HashService.sha256Hex(adulterada.canonicalJson().getBytes(StandardCharsets.UTF_8));
            falsario.append(new LedgerEntry(indice, adulterada.created(), adulterada.keyId(),
                    adulterada.subject(), adulterada.manifestSha256(), prev, hash).toJsonLine())
                    .append(System.lineSeparator());
            prev = hash;
            indice++;
        }
        Files.writeString(ledger, falsario.toString());
    }
}
