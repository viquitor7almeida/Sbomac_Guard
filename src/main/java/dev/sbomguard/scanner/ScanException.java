package dev.sbomguard.scanner;

public class ScanException extends RuntimeException {

    public ScanException(String message) {
        super(message);
    }

    public ScanException(String message, Throwable cause) {
        super(message, cause);
    }
}
