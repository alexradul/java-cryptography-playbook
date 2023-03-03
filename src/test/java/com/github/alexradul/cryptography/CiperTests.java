package com.github.alexradul.cryptography;

import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.assertj.core.api.Assertions.assertThat;

public class CiperTests {
    @Test
    void secretKeyCryptography_basicUsage()
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException,
            InvalidKeyException {

        int AES_BLOCK_SIZE = 8;
        Charset utf8 = StandardCharsets.UTF_8;
        byte[] plainText = "Words are easy, like the wind; faithful friends are hard to find."
                .getBytes(utf8);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(192);
        SecretKey secretKey = keyGenerator.generateKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] cipherText = cipher.doFinal(plainText);

        System.out.printf("Plain text: %s%n", utf8.decode(ByteBuffer.wrap(plainText)));
        System.out.printf("Cipher text: %s%n", utf8.decode(ByteBuffer.wrap(cipherText)));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedPlainText = cipher.doFinal(cipherText);

        String decodedMessage = utf8.decode(ByteBuffer.wrap(decryptedPlainText)).toString();

        assertThat(decodedMessage).isEqualTo("Words are easy, like the wind; faithful friends are hard to find.");
        assertThat(cipherText.length % AES_BLOCK_SIZE)
                .isZero();
    }

    @Test
    void publicKeyCryptgraphy_basicUsage()
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        int keyBitLength = 1024;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keyBitLength);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        Charset utf8 = StandardCharsets.UTF_8;
        byte[] plainText = "It’s not in the stars to hold our destiny but in ourselves".getBytes(utf8);
        byte[] cipherText = cipher.doFinal(plainText);

        System.out.printf("Plain text: %s%n", utf8.decode(ByteBuffer.wrap(plainText)));
        System.out.printf("Cipher text: %s%n", utf8.decode(ByteBuffer.wrap(cipherText)));

        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedPlainText = cipher.doFinal(cipherText);

        String decodedMessage = utf8.decode(ByteBuffer.wrap(decryptedPlainText)).toString();

        assertThat(decodedMessage).isEqualTo("It’s not in the stars to hold our destiny but in ourselves");

        assertThat(cipherText.length % (keyBitLength / 8)).isZero();
        assertThat(cipherText).hasSize(keyBitLength / 8);
    }
}
