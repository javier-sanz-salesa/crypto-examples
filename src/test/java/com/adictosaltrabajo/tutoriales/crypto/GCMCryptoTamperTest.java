package com.adictosaltrabajo.tutoriales.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

import static org.junit.Assert.assertEquals;

/**
 * This class tests the ciphering of a plaintext in GCM mode using various algorithms and deciphering of a tampered ciphertext
 */
public class GCMCryptoTamperTest {

    private static final String PLAINTEXT = "This is a simple symmetric cryptography test using the bouncy castle library";

    private static final int KEY_LENGTH_AES_128 = 128 / 8;
    private static final int KEY_LENGTH_AES_192 = 192 / 8;
    private static final int KEY_LENGTH_AES_256 = 256 / 8;
    private static final int KEY_LENGTH_TWOFISH_128 = 128 / 8;
    private static final int KEY_LENGTH_TWOFISH_192 = 192 / 8;
    private static final int KEY_LENGTH_TWOFISH_256 = 256 / 8;

    @Test(expected = InvalidCipherTextException.class)
    public void testAESMode128() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_128, new AESEngine());
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testAESMode192() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_192, new AESEngine());
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testAESMode256() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_256, new AESEngine());
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testTwoFishMode128() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_128, new TwofishEngine());
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testTwoFishMode192() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_192, new TwofishEngine());
    }

    @Test(expected = InvalidCipherTextException.class)
    public void testTwoFishMode256() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_256, new TwofishEngine());
    }

    /**
     * Get a random byte array
     *
     * @param length The array length
     * @return The random array
     */
    private static byte[] getRandomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte[] result = new byte[length];
        random.nextBytes(result);
        return result;
    }

    /**
     * Perform a test with the input parameter values
     *
     * @param keyLength The key length
     * @param engine    The cipher engine
     * @throws InvalidCipherTextException
     */
    private void performTest(int keyLength, BlockCipher engine) throws InvalidCipherTextException {
        byte[] key = getRandomBytes(keyLength);

        byte[] cipherText = CryptoExamples.cipherInGCMMode(
                getPlaintextBytes(PLAINTEXT),
                key,
                getRandomBytes(CryptoExamples.NONCE_SIZE_GCM),
                engine);

        cipherText = tamperByteArray(cipherText);

        engine.reset();

        String plaintext = CryptoExamples.decipherInGCMMode(cipherText, key, engine);

        assertEquals(PLAINTEXT, plaintext);
    }

    /**
     * Tamper the byte array by adding one to a random position of the array. If that position happens to contain the max byte value, the value loops to be -127.
     *
     * @param inputArray The array to be tampered
     * @return The tampered array
     */
    private byte[] tamperByteArray(byte[] inputArray) {
        if (inputArray.length > 0) {
            SecureRandom rng = new SecureRandom();
            int tamperIndex = rng.nextInt(inputArray.length);
            inputArray[tamperIndex]++;
        }
        return inputArray;
    }

    /**
     * Extract the bytes from a String
     *
     * @param plaintext The String
     * @return The utf-8 encoded bytes of the String. If utf-8 is not present then uses the default encoding.
     */
    private byte[] getPlaintextBytes(String plaintext) {
        try {
            return plaintext.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            return plaintext.getBytes();
        }
    }
}
