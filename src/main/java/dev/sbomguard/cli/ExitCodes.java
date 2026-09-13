package dev.sbomguard.cli;

public final class ExitCodes {

    public static final int OK = 0;

    public static final int GENERIC_ERROR = 1;

    public static final int INVALID_ARGUMENT = 2;

    public static final int INTEGRITY_VIOLATION = 10;

    public static final int SIGNATURE_INVALID = 11;

    public static final int UNEXPECTED_DEPENDENCY = 12;

    public static final int MANIFEST_NOT_FOUND = 13;

    private ExitCodes() {
        throw new AssertionError("classe de contrato: não instanciável");
    }
}
