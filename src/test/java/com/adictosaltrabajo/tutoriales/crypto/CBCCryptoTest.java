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

import static org.junit.Assert.assertEquals;

/**
 * This class tests ciphering a plaintext using various symmetric algorithms in CBC mode
 */
public class CBCCryptoTest {

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

    @Test
    public void testDES64() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_DES_64, CryptoExamples.IV_SIZE_DES, new DESEngine());
    }

    @Test
    public void testTripleDESMode128() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TRIPLEDES_128, CryptoExamples.IV_SIZE_TRIPLEDES, new DESedeEngine());
    }

    @Test
    public void testTripleDESMode192() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TRIPLEDES_192, CryptoExamples.IV_SIZE_TRIPLEDES, new DESedeEngine());
    }

    @Test
    public void testAESMode128() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_128, CryptoExamples.IV_SIZE_AES, new AESEngine());
    }

    @Test
    public void testAESMode192() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_192, CryptoExamples.IV_SIZE_AES, new AESEngine());
    }

    @Test
    public void testAESMode256() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_AES_256, CryptoExamples.IV_SIZE_AES, new AESEngine());
    }

    @Test
    public void testTwofishMode128() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_128, CryptoExamples.IV_SIZE_TWOFISH, new TwofishEngine());
    }
    @Test
    public void testTwofishMode192() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_192, CryptoExamples.IV_SIZE_TWOFISH, new TwofishEngine());
    }
    @Test
    public void testTwofishMode256() throws InvalidCipherTextException {
        performTest(KEY_LENGTH_TWOFISH_256, CryptoExamples.IV_SIZE_TWOFISH, new TwofishEngine());
    }

    /**
     * Perform a test with the input parameter values
     * @param keyLength The key length
     * @param engine The cipher engine
     * @throws InvalidCipherTextException
     */
    private void performTest(int keyLength, int ivLength, BlockCipher engine) throws InvalidCipherTextException {
        byte[] key = getRandomBytes(keyLength);

        byte[] cipherText = CryptoExamples.cipherInCBCMode(
                getPlaintextBytes(PLAINTEXT),
                key,
                getRandomBytes(ivLength),
                engine);

        engine.reset();

        String plaintext = CryptoExamples.decipherInCBCMode(cipherText, key, engine, ivLength);

        assertEquals(PLAINTEXT, plaintext);
    }

    /**
     * Get a random byte array
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
     * Extract the bytes from a String
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
