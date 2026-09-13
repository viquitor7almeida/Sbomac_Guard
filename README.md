# SBOMGuard

**Integridade e proveniência verificáveis para a cadeia de suprimentos de software.**

SBOMGuard é uma CLI de segurança de cadeia de suprimentos que inventaria dependências e artefatos de um projeto, gera SBOM no padrão **CycloneDX**, produz um **manifesto de integridade** com hashes SHA-256, o **assina com Ed25519** e **verifica de forma reproduzível e offline** se o que existe no build é exatamente o que foi atestado.

Projetado para atuar como gate em pipelines CI/CD: verificação reprovada = build bloqueado, com código de saída específico para cada tipo de violação.

## Como funciona

Cinco camadas independentes, cada uma resolvendo um problema distinto:

| Camada | Problema que resolve | Mecanismo |
|---|---|---|
| **Integridade** | "este arquivo é o mesmo de antes?" | Hash SHA-256 por artefato |
| **Autenticidade** | "quem produziu este manifesto?" | Assinatura Ed25519 |
| **Proveniência** | "do que este software é feito?" | SBOM CycloneDX + metadados de build |
| **Auditoria** | "o que foi atestado ao longo do tempo?" | Ledger append-only com hash chaining |
| **Política** | "quando bloquear um build?" | Exit codes determinísticos consumidos pelo CI |

Fluxo de uso:

1. `scan` — inventaria o projeto: dependências Maven, artefatos, arquivos relevantes
2. `sbom` — materializa o inventário como SBOM CycloneDX (JSON), validado por schema
3. `attest` — gera o manifesto de integridade: cada componente com seu hash SHA-256
4. `sign` — assina o manifesto com Ed25519; chaves ficam com você, nunca no repositório
5. `verify` — re-executa a medição e compara com o manifesto assinado; qualquer divergência (arquivo alterado, dependência a mais ou a menos) reprova com exit code específico

> A superfície de comandos acima define a CLI. O que está disponível na sua versão aparece em `sbomguard --help`.

## O que garante — e o que não garante

**Garante**, dentro do modelo de confiança definido pelas chaves:

- **Integridade**: alteração de 1 byte em qualquer artefato registrado é detectada
- **Autenticidade**: manifesto adulterado não passa na verificação de assinatura
- **Proveniência**: o SBOM registra exatamente o que entrou no build

**Não garante**:

- Não é antivírus — detecta **alteração**, não **malícia**; componente malicioso registrado antes do ataque verifica com sucesso
- Não protege ambiente totalmente comprometido — runner que mente durante o `verify`, ou chave privada comprometida, estão fora do alcance da ferramenta
- Não avalia vulnerabilidades (CVEs) — o escopo é integridade e proveniência, não análise de risco

## Instalação

Pré-requisitos: JDK 21 (LTS), Maven 3.9+.

```bash
git clone <url-do-repositorio> sbomguard
cd sbomguard
mvn verify
```

Executar em desenvolvimento:

```bash
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes:$(cat target/cp.txt)" dev.sbomguard.SbomGuardCli --help
```

## Códigos de saída

Contrato consumido por pipelines CI/CD:

| Código | Constante | Significado |
|-------:|-----------|-------------|
| 0 | `OK` | Sucesso / verificação aprovada |
| 1 | `GENERIC_ERROR` | Erro interno da ferramenta |
| 2 | `INVALID_ARGUMENT` | Argumento inválido |
| 10 | `INTEGRITY_VIOLATION` | Hash de artefato diverge do registrado |
| 11 | `SIGNATURE_INVALID` | Assinatura inválida ou ausente |
| 12 | `UNEXPECTED_DEPENDENCY` | Dependência fora do manifesto |
| 13 | `MANIFEST_NOT_FOUND` | Manifesto esperado não existe |

Códigos 1–2 indicam falha da ferramenta; códigos 10–13 indicam que a ferramenta funcionou e o build deve ser bloqueado.

## Arquitetura

```
dev.sbomguard/
├── SbomGuardCli    # comando raiz
├── cli/            # comandos e contrato de exit codes
├── crypto/         # SHA-256 e Ed25519 (implementações nativas do JDK)
├── scanner/        # inventário de componentes e artefatos
├── sbom/           # geração e validação CycloneDX
├── manifest/       # manifesto de integridade versionado
├── verification/   # motor de verificação
├── ledger/         # registro de atestados (append-only)
└── policy/         # regras de bloqueio
```

## Segurança do próprio SBOMGuard

- Criptografia **100% JDK** — SHA-256 e Ed25519 nativos, zero dependências criptográficas externas
- Dependências mínimas e pinadas: picocli, maven-model, cyclonedx-core-java (OWASP), jackson
- Chaves privadas nunca versionadas — o `.gitignore` bloqueia `*.pem`, `*.key`, `*.p12`, `*.jks`
