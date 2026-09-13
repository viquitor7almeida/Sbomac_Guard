package dev.sbomguard.ledger;

import dev.sbomguard.crypto.SignatureService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

public final class AnchorService {

    public static final String ANCHOR_FILE = "sbomguard.anchor.json";

    public record AnchorCheck(boolean anchorSignatureValid, boolean intact, List<String> problems) {
    }

    public Anchor create(Path ledgerFile, PrivateKey privateKey, String keyId) throws IOException {
        LedgerService ledger = new LedgerService();
        LedgerService.ChainVerification chain = ledger.verifyChain(ledgerFile);
        if (!chain.intact()) {
            throw new IOException("ledger com cadeia quebrada — recusa em ancorar: " + chain.problems().get(0));
        }
        List<LedgerEntry> entries = ledger.readAll(ledgerFile);
        String head = entries.isEmpty() ? LedgerService.GENESIS
                : entries.get(entries.size() - 1).entryHash();

        Anchor semAssinatura = new Anchor(head, entries.size(),
                java.time.Instant.now().toString(), keyId, null);
        byte[] assinatura = new SignatureService().sign(
                semAssinatura.canonicalJson().getBytes(StandardCharsets.UTF_8), privateKey);
        return new Anchor(semAssinatura.ledgerHead(), semAssinatura.entryCount(),
                semAssinatura.created(), keyId,
                java.util.Base64.getEncoder().encodeToString(assinatura));
    }

    public AnchorCheck verify(Path ledgerFile, Path anchorFile, PublicKey publicKey) throws IOException {
        Anchor anchor;
        try {
            anchor = Anchor.deserialize(Files.readString(anchorFile, StandardCharsets.UTF_8));
        } catch (IOException | IllegalArgumentException e) {
            return new AnchorCheck(false, false,
                    List.of("âncora ilegível: " + anchorFile + " — " + e.getMessage()));
        }
        if (anchor.signatureBase64() == null) {
            return new AnchorCheck(false, false, List.of("âncora sem assinatura"));
        }

        byte[] canonico = anchor.canonicalJson().getBytes(StandardCharsets.UTF_8);
        if (!new SignatureService().verify(canonico, anchor.signatureBytes(), publicKey)) {
            return new AnchorCheck(false, false,
                    List.of("assinatura da âncora inválida — âncora adulterada ou chave errada"));
        }

        List<String> problems = new ArrayList<>();
        if (anchor.entryCount() > 0 && !Files.isRegularFile(ledgerFile)) {
            problems.add("ledger inexistente, mas a âncora atesta " + anchor.entryCount()
                    + " entradas — deleção total detectada pela âncora");
        }

        LedgerService ledger = new LedgerService();
        LedgerService.ChainVerification chain = ledger.verifyChain(ledgerFile);
        if (!chain.intact()) {
            problems.addAll(chain.problems());
        } else {
            List<LedgerEntry> entries = ledger.readAll(ledgerFile);
            String headLocal = entries.isEmpty() ? LedgerService.GENESIS
                    : entries.get(entries.size() - 1).entryHash();
            if (!anchor.ledgerHead().equals(headLocal)) {
                problems.add("head do ledger diverge da âncora: local " + prefixo(headLocal)
                        + " vs âncora " + prefixo(anchor.ledgerHead()) + " — reescrita ou truncamento");
            }
            if (anchor.entryCount() != entries.size()) {
                problems.add("contagem diverge: âncora atesta " + anchor.entryCount()
                        + " entradas, o ledger local tem " + entries.size());
            }
        }
        return new AnchorCheck(true, problems.isEmpty(), List.copyOf(problems));
    }

    private String prefixo(String hash) {
        return hash.substring(0, 12) + "…";
    }
}
