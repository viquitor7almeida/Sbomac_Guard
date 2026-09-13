package dev.sbomguard.policy;

import dev.sbomguard.verification.VerificationEngine.Finding;
import dev.sbomguard.verification.VerificationEngine.FindingKind;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class VerificationPolicyTest {

    private final VerificationPolicy policy = new VerificationPolicy();

    private Finding finding(FindingKind kind) {
        return new Finding(kind, "mensagem");
    }

    @Test
    void semFindingsEhAprovado() {
        assertEquals(VerificationPolicy.Verdict.APROVADO, policy.verdict(List.of()));
    }

    @Test
    void apenasInesperadosEhComponenteInesperado() {
        assertEquals(VerificationPolicy.Verdict.COMPONENTE_INESPERADO,
                policy.verdict(List.of(finding(FindingKind.COMPONENTE_INESPERADO))));
    }

    @Test
    void qualquerViolaçãoDeIntegridadePrevalece() {
        assertEquals(VerificationPolicy.Verdict.INTEGRIDADE_COMPROMETIDA,
                policy.verdict(List.of(
                        finding(FindingKind.COMPONENTE_INESPERADO),
                        finding(FindingKind.HASH_DIVERGENTE))));
        assertEquals(VerificationPolicy.Verdict.INTEGRIDADE_COMPROMETIDA,
                policy.verdict(List.of(finding(FindingKind.COMPONENTE_AUSENTE))));
        assertEquals(VerificationPolicy.Verdict.INTEGRIDADE_COMPROMETIDA,
                policy.verdict(List.of(finding(FindingKind.SBOM_DIVERGENTE))));
        assertEquals(VerificationPolicy.Verdict.INTEGRIDADE_COMPROMETIDA,
                policy.verdict(List.of(finding(FindingKind.SBOM_AUSENTE))));
    }

    @Test
    void hashDivergenteIsoladoEhIntegridadeComprometida() {
        assertEquals(VerificationPolicy.Verdict.INTEGRIDADE_COMPROMETIDA,
                policy.verdict(List.of(finding(FindingKind.HASH_DIVERGENTE))));
    }
}
