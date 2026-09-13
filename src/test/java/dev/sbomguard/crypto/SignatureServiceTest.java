package dev.sbomguard.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureServiceTest {

    private final SignatureService service = new SignatureService();
    private KeyPair par;
    private KeyPair outroPar;

    @BeforeEach
    void geraChaves() throws NoSuchAlgorithmException {
        par = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        outroPar = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void assinaEVerificaComSucesso() {
        byte[] assinatura = service.sign(bytes("manifesto original"), par.getPrivate());

        assertTrue(service.verify(bytes("manifesto original"), assinatura, par.getPublic()));
    }

    @Test
    void assinaturaEDeterministicaParaMesmaChaveEConteudo() {
        byte[] a1 = service.sign(bytes("mesmo conteúdo"), par.getPrivate());
        byte[] a2 = service.sign(bytes("mesmo conteúdo"), par.getPrivate());

        assertArrayEquals(a1, a2, "Ed25519 é determinístico (RFC 8032): mesma entrada, mesma assinatura");
    }

    @Test
    void alterarUmBitDoConteudoInvalidaAssinatura() {
        byte[] conteudo = bytes("manifesto original");
        byte[] assinatura = service.sign(conteudo, par.getPrivate());

        byte[] alterado = conteudo.clone();
        alterado[3] ^= 0x01;

        assertFalse(service.verify(alterado, assinatura, par.getPublic()),
                "1 bit no manifesto assinado deve invalidar a assinatura");
    }

    @Test
    void alterarUmBitDaAssinaturaInvalidaVerificacao() {
        byte[] conteudo = bytes("manifesto original");
        byte[] assinatura = service.sign(conteudo, par.getPrivate());

        byte[] assinaturaAlterada = assinatura.clone();
        assinaturaAlterada[10] ^= 0x01;

        assertFalse(service.verify(conteudo, assinaturaAlterada, par.getPublic()));
    }

    @Test
    void chaveDiferenteNaoValidaAssinatura() {
        byte[] assinatura = service.sign(bytes("conteúdo"), par.getPrivate());

        assertFalse(service.verify(bytes("conteúdo"), assinatura, outroPar.getPublic()));
    }

    @Test
    void assinaturaVaziaOuTruncadaRetornaFalseNuncaExcecao() {
        byte[] conteudo = bytes("conteúdo");

        assertFalse(service.verify(conteudo, new byte[0], par.getPublic()),
                "assinatura vazia é resultado falso, não exceção");
        assertFalse(service.verify(conteudo, new byte[63], par.getPublic()),
                "assinatura truncada é resultado falso, não exceção");
    }
}
