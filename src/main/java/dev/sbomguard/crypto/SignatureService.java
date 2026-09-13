package dev.sbomguard.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

public final class SignatureService {

    public byte[] sign(byte[] content, PrivateKey privateKey) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(content);
            return sig.sign();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK sem Ed25519: ambiente sem suporte ao EdDSA", e);
        } catch (InvalidKeyException | SignatureException e) {
            throw new CryptoException("falha ao assinar: " + e.getMessage(), e);
        }
    }

    public boolean verify(byte[] content, byte[] signature, PublicKey publicKey) {
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(content);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK sem Ed25519: ambiente sem suporte ao EdDSA", e);
        } catch (InvalidKeyException e) {
            throw new CryptoException("falha na verificação: " + e.getMessage(), e);
        } catch (SignatureException e) {

            return false;
        }
    }
}
