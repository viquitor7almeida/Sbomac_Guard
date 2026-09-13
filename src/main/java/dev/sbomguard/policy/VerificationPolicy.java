package dev.sbomguard.policy;

import dev.sbomguard.verification.VerificationEngine.Finding;
import dev.sbomguard.verification.VerificationEngine.FindingKind;

import java.util.List;

public final class VerificationPolicy {

    public enum Verdict {
        APROVADO, INTEGRIDADE_COMPROMETIDA, COMPONENTE_INESPERADO
    }

    public Verdict verdict(List<Finding> findings) {
        boolean integridade = findings.stream()
                .anyMatch(f -> f.kind() != FindingKind.COMPONENTE_INESPERADO);
        boolean inesperado = findings.stream()
                .anyMatch(f -> f.kind() == FindingKind.COMPONENTE_INESPERADO);

        if (integridade) {
            return Verdict.INTEGRIDADE_COMPROMETIDA;
        }
        if (inesperado) {
            return Verdict.COMPONENTE_INESPERADO;
        }
        return Verdict.APROVADO;
    }
}
