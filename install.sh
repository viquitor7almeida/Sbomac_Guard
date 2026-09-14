#!/bin/sh
set -eu

BIN_DIR="$HOME/.local/bin"
JAR_DIR="$HOME/.local/share/sbomguard"
JAR_FILE="$JAR_DIR/sbomguard.jar"
WRAPPER="$BIN_DIR/sbomguard"

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$WRAPPER" "$JAR_FILE"
    rmdir "$JAR_DIR" 2>/dev/null || true
    printf 'sbomguard desinstalado (a linha de PATH no arquivo de shell permanece; remova-a manualmente se quiser).\n'
    exit 0
fi

if ! command -v java >/dev/null 2>&1; then
    printf 'erro: java (JDK 21) não encontrado no PATH.\n' >&2
    exit 1
fi

JAR_BUILD=$(find target -maxdepth 1 -name 'sbomguard-*.jar' ! -name 'original-*' 2>/dev/null | head -n 1)
if [ -z "$JAR_BUILD" ]; then
    if ! command -v mvn >/dev/null 2>&1; then
        printf 'erro: rode "mvn verify" antes de instalar (Maven não encontrado).\n' >&2
        exit 1
    fi
    printf 'jar ausente: buildando com "mvn -q verify" (inclui os testes)...\n'
    mvn -q verify
    JAR_BUILD=$(find target -maxdepth 1 -name 'sbomguard-*.jar' ! -name 'original-*' | head -n 1)
fi

mkdir -p "$BIN_DIR" "$JAR_DIR"
cp "$JAR_BUILD" "$JAR_FILE"

printf '#!/bin/sh\nexec java -jar "$HOME/.local/share/sbomguard/sbomguard.jar" "$@"\n' > "$WRAPPER"
chmod +x "$WRAPPER"

PATH_LINE='export PATH="$HOME/.local/bin:$PATH"'
case "${SHELL:-}" in
    *zsh*)  RC_FILE="$HOME/.zshenv" ;;
    *bash*) RC_FILE="$HOME/.bashrc" ;;
    *)      RC_FILE="$HOME/.profile" ;;
esac
if ! grep -qF "$PATH_LINE" "$RC_FILE" 2>/dev/null; then
    printf '%s\n' "$PATH_LINE" >> "$RC_FILE"
    printf 'PATH atualizado em %s\n' "$RC_FILE"
fi

if ! "$WRAPPER" --version >/dev/null 2>&1; then
    printf 'erro: autoverificação falhou — o comando instalado não respondeu.\n' >&2
    exit 1
fi

printf 'instalado: sbomguard (%s)\n' "$("$WRAPPER" --version)"
printf 'abra um novo terminal (ou: source %s) e use "sbomguard --help" de qualquer diretório.\n' "$RC_FILE"
printf 'atualizar versão: mvn -q package && ./install.sh\n'
