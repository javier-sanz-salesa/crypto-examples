package com.adictosaltrabajo.tutoriales.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;

/**
 * This class tests the performance of different cipher suites.
 */
public class PerformanceCryptoTest {
    private static final String PLAINTEXT = "This is a simple symmetric cryptography test using the bouncy castle library";

    private static final int KEY_LENGTH_DES_64 = 64 / 8;
    private static final int KEY_LENGTH_TRIPLEDES_128 = 128 / 8;
    private static final int KEY_LENGTH_TRIPLEDES_192 = 192 / 8;
    private static final int KEY_LENGTH_AES_128 = 128 / 8;
    private static final int KEY_LENGTH_AES_192 = 192 / 8;
    private static final int KEY_LENGTH_AES_256 = 256 / 8;
    private static final int KEY_LENGTH_TWOFISH_128 = 128 / 8;
    private static final int KEY_LENGTH_TWOFISH_192 = 192 / 8;
    private static final int KEY_LENGTH_TWOFISH_256 = 256 / 8;

    private static final int IV_LENGTH_DES = 64 / 8;
    private static final int IV_LENGTH_TRIPLEDES = 64 / 8;
    private static final int IV_LENGTH_AES = 128 / 8;
    private static final int IV_LENGTH_TWOFISH = 128 / 8;

    private static final int NUMBER_OF_OPERATIONS = 50_000;

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

    private byte[] performGCMCipher(byte[] plaintext, byte[] key, byte[] nonce, BlockCipher engine) throws InvalidCipherTextException {
        return CryptoExamples.cipherInGCMMode(plaintext, key, nonce, engine);
    }

    private void performGCMDecipher(byte[] cipherText, byte[] key, BlockCipher engine) throws InvalidCipherTextException {
        CryptoExamples.decipherInGCMMode(cipherText, key, engine);
    }

    private byte[] performCBCCipher(byte[] plaintext, byte[] key, byte[] iv, BlockCipher engine) throws InvalidCipherTextException {
        return CryptoExamples.cipherInCBCMode(plaintext, key, iv, engine);
    }

    private void performCBCDecipher(byte[] cipherText, byte[] key, BlockCipher engine, int ivSize) throws InvalidCipherTextException {
        CryptoExamples.decipherInCBCMode(cipherText, key, engine, ivSize);
    }

    private void performGCMTest(int keyLength, BlockCipher engine, String testName) throws InvalidCipherTextException {
        byte[] key = getRandomBytes(keyLength);
        byte[] plaintext = getPlaintextBytes(PLAINTEXT);
        byte[] nonce = getRandomBytes(CryptoExamples.NONCE_SIZE_GCM);

        byte[][] cipherTexts = new byte[NUMBER_OF_OPERATIONS][];

        long cipherBeginTime = System.nanoTime();

        for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
            cipherTexts[i] = performGCMCipher(plaintext, key, nonce, engine);
        }

        long cipherEndTime = System.nanoTime();
        long decipherBeginTime = System.nanoTime();

        for (int j = 0; j < NUMBER_OF_OPERATIONS; j++) {
            performGCMDecipher(cipherTexts[j], key, engine);
        }

        long decipherEndTime = System.nanoTime();

        long mediumCipherTime = (cipherEndTime - cipherBeginTime) / NUMBER_OF_OPERATIONS;
        long mediumDecipherTime = (decipherEndTime - decipherBeginTime) / NUMBER_OF_OPERATIONS;

        System.out.println(testName + " cipher = " + mediumCipherTime + " ns medium operation");
        System.out.println(testName + " decipher = " + mediumDecipherTime + " ns medium operation");
    }

    private void performCBCTest(int keyLength, int ivLength, BlockCipher engine, String testName) throws InvalidCipherTextException {
        byte[] key = getRandomBytes(keyLength);
        byte[] plaintext = getPlaintextBytes(PLAINTEXT);
        byte[] iv = getRandomBytes(ivLength);

        byte[][] cipherTexts = new byte[NUMBER_OF_OPERATIONS][];

        long cipherBeginTime = System.nanoTime();

        for (int i = 0; i < NUMBER_OF_OPERATIONS; i++) {
            cipherTexts[i] = performCBCCipher(plaintext, key, iv, engine);
        }

        long cipherEndTime = System.nanoTime();
        long decipherBeginTime = System.nanoTime();

        for (int j = 0; j < NUMBER_OF_OPERATIONS; j++) {
            performCBCDecipher(cipherTexts[j], key, engine, ivLength);
        }

        long decipherEndTime = System.nanoTime();

        long mediumCipherTime = (cipherEndTime - cipherBeginTime) / NUMBER_OF_OPERATIONS;
        long mediumDecipherTime = (decipherEndTime - decipherBeginTime) / NUMBER_OF_OPERATIONS;

        System.out.println(testName + " cipher = " + mediumCipherTime + " ns medium operation");
        System.out.println(testName + " decipher = " + mediumDecipherTime + " ns medium operation");
    }

    @Test
    public void testCBCModeDES64() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_DES_64, IV_LENGTH_DES, new DESEngine(), "DES-64 in CBC mode");
    }

    @Test
    public void testCBCModeTripleDES128() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_TRIPLEDES_128, IV_LENGTH_TRIPLEDES, new DESedeEngine(), "TDES-128 in CBC mode");
    }

    @Test
    public void testCBCModeTripleDES192() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_TRIPLEDES_192, IV_LENGTH_TRIPLEDES, new DESedeEngine(), "TDES-192 in CBC mode");
    }

    @Test
    public void testCBCModeAES128() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_AES_128, IV_LENGTH_AES, new AESEngine(), "AES-128 in CBC mode");
    }

    @Test
    public void testCBCModeAES192() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_AES_192, IV_LENGTH_AES, new AESEngine(), "AES-192 in CBC mode");
    }

    @Test
    public void testCBCModeAES256() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_AES_256, IV_LENGTH_AES, new AESEngine(), "AES-256 in CBC mode");
    }

    @Test
    public void testCBCModeTwoFish128() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_TWOFISH_128, IV_LENGTH_TWOFISH, new TwofishEngine(), "TWOFISH-128 in CBC mode");
    }

    @Test
    public void testCBCModeTwoFish192() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_TWOFISH_192, IV_LENGTH_TWOFISH, new TwofishEngine(), "TWOFISH-192 in CBC mode");
    }

    @Test
    public void testCBCModeTwoFish256() throws InvalidCipherTextException {
        performCBCTest(KEY_LENGTH_TWOFISH_256, IV_LENGTH_TWOFISH, new TwofishEngine(), "TWOFISH-256 in CBC mode");
    }

    @Test
    public void testGCMModeAES128() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_AES_128, new AESEngine(), "AES-128 in GCM mode");
    }

    @Test
    public void testGCMModeAES192() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_AES_192, new AESEngine(), "AES-192 in GCM mode");
    }

    @Test
    public void testGCMModeAES256() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_AES_256, new AESEngine(), "AES-256 in GCM mode");
    }

    @Test
    public void testGCMModeTwofish128() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_TWOFISH_128, new TwofishEngine(), "TWOFISH-128 in GCM mode");
    }

    @Test
    public void testGCMModeTwofish192() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_TWOFISH_192, new TwofishEngine(), "TWOFISH-192 in GCM mode");
    }

    @Test
    public void testGCMModeTwofish256() throws InvalidCipherTextException {
        performGCMTest(KEY_LENGTH_TWOFISH_256, new TwofishEngine(), "TWOFISH-256 in GCM mode");
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
