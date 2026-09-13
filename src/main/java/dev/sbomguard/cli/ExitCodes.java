package dev.sbomguard.cli;

/**
 * Contrato de exit codes do SBOMGuard — interface consumida por pipelines CI/CD.
 *
 * Faixas:
 *   0–2  : operação da ferramenta (sucesso, erro genérico, argumento inválido)
 *   10–13: resultado de SEGURANÇA — a ferramenta funcionou e detectou algo.
 *
 * Distinção crítica para CI/CD: exit 10 significa "verificação EXECUTADA e
 * REPROVADA", não "ferramenta quebrou". Um pipeline deve tratá-los de forma
 * diferente (bloquear deploy vs. investigar bug da ferramenta).
 */
public final class ExitCodes {

    /** Operação concluída com sucesso (ou verificação aprovada). */
    public static final int OK = 0;

    /** Erro genérico: exceção interna, IO inesperado, estado inconsistente. */
    public static final int GENERIC_ERROR = 1;

    /** Argumento inválido informado pelo usuário (compatível com convenção Unix). */
    public static final int INVALID_ARGUMENT = 2;

    /** Verificação de integridade reprovada: hash de artefato divergente do registrado. */
    public static final int INTEGRITY_VIOLATION = 10;

    /** Assinatura digital inválida ou ausente no manifesto. */
    public static final int SIGNATURE_INVALID = 11;

    /** Dependência presente no build que não consta no manifesto/SBOM. */
    public static final int UNEXPECTED_DEPENDENCY = 12;

    /** Manifesto de integridade esperado não encontrado. */
    public static final int MANIFEST_NOT_FOUND = 13;

    private ExitCodes() {
        throw new AssertionError("classe de contrato: não instanciável");
    }
}
