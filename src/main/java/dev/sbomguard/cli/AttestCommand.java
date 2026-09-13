package dev.sbomguard.cli;

import dev.sbomguard.SbomGuardCli;
import dev.sbomguard.manifest.Manifest;
import dev.sbomguard.manifest.ManifestBuilder;
import dev.sbomguard.manifest.ManifestCodec;
import dev.sbomguard.sbom.SbomGenerator;
import dev.sbomguard.scanner.ProjectScanner;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Spec;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;

@Command(
        name = "attest",
        mixinStandardHelpOptions = true,
        description = "Gera o atestado completo: escaneia, materializa o SBOM e grava o manifesto de integridade."
)
public class AttestCommand implements Callable<Integer> {

    public static final String SBOM_FILE_NAME = "sbomguard.sbom.json";
    public static final String MANIFEST_FILE_NAME = "sbomguard.manifest.json";

    @Spec
    CommandSpec spec;

    @Parameters(arity = "1", paramLabel = "DIRETÓRIO", description = "Raiz do projeto a atestar.")
    private Path directory;

    @Option(names = {"--output-dir"}, paramLabel = "DIRETÓRIO",
            description = "Onde gravar SBOM e manifesto (default: a própria raiz do projeto). Criado se não existir.")
    private Path outputDir;

    @Override
    public Integer call() {
        CommandLine cmd = spec.commandLine();
        try {
            ProjectScanner.ScanResult scan = new ProjectScanner().scan(directory);
            SbomGenerator generator = new SbomGenerator();
            Bom bom = generator.generate(scan, UUID.randomUUID());
            String sbomJson = generator.toJson(bom);

            List<ParseException> errosValidacao = generator.validate(sbomJson);
            if (!errosValidacao.isEmpty()) {
                cmd.getErr().println("erro interno: SBOM gerado não passou na validação de schema:");
                errosValidacao.forEach(e -> cmd.getErr().println("  - " + e.getMessage()));
                return ExitCodes.GENERIC_ERROR;
            }

            Path destino = (outputDir != null) ? outputDir : scan.root();
            Files.createDirectories(destino);
            Path sbomPath = destino.resolve(SBOM_FILE_NAME);
            Files.writeString(sbomPath, sbomJson);

            Manifest manifest = new ManifestBuilder().build(scan, sbomPath,
                    new Manifest.Tool("sbomguard", SbomGuardCli.VERSION));
            ManifestCodec codec = new ManifestCodec();
            String manifestJson = codec.serialize(manifest);
            Path manifestPath = destino.resolve(MANIFEST_FILE_NAME);
            Files.writeString(manifestPath, manifestJson);

            for (Path link : scan.skippedSymlinks()) {
                cmd.getErr().println("aviso: symlink pulado: " + link);
            }
            for (String erroPom : scan.pomErrors()) {
                cmd.getErr().println("aviso: " + erroPom);
            }
            if (!scan.pomFound()) {
                cmd.getErr().println("aviso: nenhum pom.xml legível — atestado apenas de artefatos de arquivo");
            }

            long hasheados = manifest.components().stream()
                    .filter(c -> c.sha256() != null).count();
            String sujeito = manifest.subject() != null
                    ? manifest.subject().group() + ":" + manifest.subject().name()
                    + ":" + manifest.subject().version()
                    : "(sem pom — projeto não identificado)";
            cmd.getOut().println("sujeito: " + sujeito);
            cmd.getOut().println("componentes: " + manifest.components().size()
                    + " (" + hasheados + " com hash)");
            cmd.getOut().println("sbom: " + sbomPath + " (sha256 " + manifest.sbom().sha256() + ")");
            cmd.getOut().println("manifesto: " + manifestPath);
            cmd.getOut().println("sha256 do manifesto: " + codec.sha256Hex(manifestJson));
            return ExitCodes.OK;
        } catch (NoSuchFileException e) {
            cmd.getErr().println("erro: " + e.getFile() + " não é um diretório (ou não existe)");
            return ExitCodes.GENERIC_ERROR;
        } catch (GeneratorException | IOException e) {
            cmd.getErr().println("erro ao atestar: " + e.getMessage());
            return ExitCodes.GENERIC_ERROR;
        }
    }
}
