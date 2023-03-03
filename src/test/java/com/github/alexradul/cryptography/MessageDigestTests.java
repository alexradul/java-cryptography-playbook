package com.github.alexradul.cryptography;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static org.apache.commons.codec.binary.Hex.encodeHexString;
import static org.assertj.core.api.Assertions.assertThat;

public class MessageDigestTests {
    @Test
    void basicUsage() throws NoSuchAlgorithmException {
        // The purpose of MessageDigest is to create a cryptographic checksum of an input message.
        var inputMessage = "What is life if not a shadow of a fleeting dream?"
                .getBytes(StandardCharsets.UTF_8);

        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] digest = md.digest(inputMessage);

        assertThat(digest).asHexString().isEqualTo("BC413C168027C465D5BD9DAFCACC7EE00546B1FD");
    }

    @Test
    void messageDigest_HasExpectedLength() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        byte[] digest = messageDigest
                .digest("Love all, trust a few, be wrong to none"
                        .getBytes(StandardCharsets.UTF_8));

        assertThat(digest.length)
                .isEqualTo(messageDigest.getDigestLength())
                .isEqualTo(256 / 8);
    }

    @Test
    void messageDigest_AlwaysHasTheSameLength() throws NoSuchAlgorithmException {
        // No matter how long the input text is, cryptographic checksum/hash functions
        // provide constant length output hash
        var shortInputMessage = "To be or not to be, it is the question".getBytes(StandardCharsets.UTF_8);
        var longInputMessage = (
                "Men at some time are masters of their fates: " +
                        "The fault, dear Brutus, is not in our stars, " +
                        "But in ourselves, that we are underlings.")
                .getBytes(StandardCharsets.UTF_8);

        var veryLongInputMessage = new byte[1024];
        new Random().nextBytes(veryLongInputMessage);

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");

        var shortInputDigest = messageDigest.digest(shortInputMessage);
        var longInputDigest = messageDigest.digest(longInputMessage);
        var veryLongInputDigest = messageDigest.digest(veryLongInputMessage);

        assertThat(shortInputDigest.length)
                .isEqualTo(longInputDigest.length)
                .isEqualTo(veryLongInputDigest.length)
                .isEqualTo(messageDigest.getDigestLength())
                .isEqualTo(256 / 8);
    }

    /**
     * This test illustrates why message digest matter. The modified_Copy contains cyrillic letter 'o' instead of latin one.
     * Therefore, the digest produced using the copy does not match the originalQuote, even though visually there is no difference.
     */
    @Test
    void smallVariationOfInput_bigVariationOfChecksum() throws NoSuchAlgorithmException {
        String originalQuote = "Shoot for the moon. Even if you miss you will land among the stars.";
        String modified_Copy = "Shoot for the moоn. Even if you miss you will land among the stars.";

        MessageDigest digestEngine = MessageDigest.getInstance("SHA-512");

        byte[] originalDigest = digestEngine.digest(originalQuote.getBytes(StandardCharsets.UTF_8));
        byte[] checkDigest = digestEngine.digest(modified_Copy.getBytes(StandardCharsets.UTF_8));


        assertThat(originalDigest)
                .asHexString()
                .isEqualTo(encodeHexString(checkDigest).toUpperCase());

        assertThat(MessageDigest.isEqual(originalDigest, checkDigest)).isTrue();
    }
}
