package com.github.alexradul.cryptography;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;

public class SignatureTests {
    @Test
    void basicUsage() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Signature signatureEngine = Signature.getInstance("SHA256withRSA");
        signatureEngine.initSign(keyPair.getPrivate());

        byte[] inputMessage = "We know what we are, but not what we may be.".getBytes(StandardCharsets.UTF_8);
        signatureEngine.update(inputMessage);
        byte[] signature = signatureEngine.sign();

        // TODO: as a reminder, use slightly modified input message
        signatureEngine.initVerify(keyPair.getPublic());
        signatureEngine.update(inputMessage);
        boolean isValidSignature = signatureEngine.verify(signature);

        assertThat(isValidSignature).isTrue();
    }
}
