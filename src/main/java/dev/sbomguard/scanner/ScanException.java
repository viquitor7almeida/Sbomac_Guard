package dev.sbomguard.scanner;

/**
 * Falha irrecoverável de scan: pom malformado, coordenadas ausentes/inválidas
 * ou erro de leitura durante o parsing.unchecked para não poluir a API do
 * scanner com exceções de implementação; a CLI traduz em mensagem + exit code.
 */
public class ScanException extends RuntimeException {

    public ScanException(String message) {
        super(message);
    }

    public ScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
