package com.github.alexradul.cryptography;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.assertj.core.api.Assertions.assertThat;

public class Base64JWTMACTests {
    @Test
    void decodeAndDecoupleJWT() throws NoSuchAlgorithmException, InvalidKeyException {
        String header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        String payload = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";
        String signature = "rRbHy8V7UMDF5KFDMJxXNBoN9iWMpCpiAAW6hNJx0O0";

        Base64.Decoder base64Decoder = Base64.getDecoder();

        byte[] headerBytes = base64Decoder.decode(header);
        byte[] payloadBytes = base64Decoder.decode(payload);
        byte[] signatureBytes = base64Decoder.decode(signature);

        dumpValues(header, payload, signature, headerBytes, payloadBytes, signatureBytes);

        String algorithm = "HmacSHA256";
        String key = "your-256-bit-secret-or-longer";

        // define key
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);

        // create MAC algorithm
        Mac mac = Mac.getInstance(algorithm);

        mac.init(secretKeySpec);

        String tokenWithoutSignature = header + "." + payload;

        byte[] macBytes = mac.doFinal(tokenWithoutSignature.getBytes(StandardCharsets.US_ASCII));

        assertThat(signatureBytes)
                .asHexString()
                .isEqualToIgnoringCase(encodeHexString(macBytes));
    }

    private void dumpValues(String header, String payload, String signature, byte[] headerBytes, byte[] payloadBytes, byte[] signatureBytes) {
        System.out.printf("Header: %s\n", new String(headerBytes, StandardCharsets.US_ASCII));
        System.out.printf("Base64: %s\n", header);
        System.out.printf("Hex...: %s\n\n", encodeHexString(headerBytes));

        System.out.printf("Payload: %s\n", new String(payloadBytes, StandardCharsets.US_ASCII));
        System.out.printf("Base64: %s\n", payload);
        System.out.printf("Hex...: %s\n\n", encodeHexString(payloadBytes));

        System.out.printf("Signature: %s\n", new String(signatureBytes, StandardCharsets.US_ASCII));
        System.out.printf("Base64: %s\n", signature);
        System.out.printf("Hex...: %s\n\n", encodeHexString(signatureBytes));
    }
}
