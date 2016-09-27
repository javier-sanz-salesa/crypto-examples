package com.adictosaltrabajo.tutoriales.crypto;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.UnsupportedEncodingException;

/**
 * This class performs simple symmetric cipher operations using the bouncy castle library.
 */
public class CryptoExamples {

    public final static int IV_SIZE_DES = 64 / 8;
    public final static int IV_SIZE_TRIPLEDES = 64 / 8;
    public final static int IV_SIZE_AES = 128 / 8;
    public final static int IV_SIZE_TWOFISH = 128 / 8;
    public final static int NONCE_SIZE_GCM = 96 / 8;
    private final static int GCM_MODE_MAC_SIZE_BITS = 128;

    public static byte[] cipherInGCMMode(byte[] plaintextBytes, byte[] key, byte[] nonce, BlockCipher engine) throws InvalidCipherTextException {
        AEADBlockCipher cipher = new GCMBlockCipher(engine);

        // Init the cipherer with key, mac size and nonce
        KeyParameter keyParameter = new KeyParameter(key);
        AEADParameters parameters = new AEADParameters(keyParameter, GCM_MODE_MAC_SIZE_BITS, nonce);
        cipher.init(true, parameters);

        int maxOutputSize = cipher.getOutputSize(plaintextBytes.length);
        byte[] cipherText = new byte[maxOutputSize];

        int outputSize = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, cipherText, 0);
        cipher.doFinal(cipherText, outputSize);

        // Append the nonce at the beginning of the ciphertext
        byte[] cipherTextWithNonce = new byte[nonce.length + cipherText.length];
        System.arraycopy(nonce, 0, cipherTextWithNonce, 0, nonce.length);
        System.arraycopy(cipherText, 0, cipherTextWithNonce, nonce.length, cipherText.length);

        return cipherTextWithNonce;
    }

    public static byte[] cipherInCBCMode(byte[] plaintextBytes, byte[] key, byte[] iv, BlockCipher engine) throws InvalidCipherTextException {
        BlockCipher cipherInOperationMode = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cipherInOperationMode, new PKCS7Padding());

        ParametersWithIV cipherInitParams = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(true, cipherInitParams);

        int maxOutputSize = cipher.getOutputSize(plaintextBytes.length);
        byte[] ciphertextBytes = new byte[maxOutputSize];

        int finalOutputSize = cipher.processBytes(plaintextBytes, 0, plaintextBytes.length, ciphertextBytes, 0);
        cipher.doFinal(ciphertextBytes, finalOutputSize);

        // Append the IV at the beginning of the ciphertext
        byte[] ciphertextWithIVBytes = new byte[iv.length + ciphertextBytes.length];
        System.arraycopy(iv, 0, ciphertextWithIVBytes, 0, iv.length);
        System.arraycopy(ciphertextBytes, 0, ciphertextWithIVBytes, iv.length, ciphertextBytes.length);

        return ciphertextWithIVBytes;
    }

    public static String decipherInGCMMode(byte[] ciphertextBytesWithNonce, byte[] key, BlockCipher engine) throws InvalidCipherTextException {
        AEADBlockCipher cipher = new GCMBlockCipher(engine);

        // Split nonce and ciphertext
        byte[] nonce = new byte[NONCE_SIZE_GCM];
        byte[] ciphertext = new byte[ciphertextBytesWithNonce.length - NONCE_SIZE_GCM];
        System.arraycopy(ciphertextBytesWithNonce, 0, nonce, 0, NONCE_SIZE_GCM);
        System.arraycopy(ciphertextBytesWithNonce, NONCE_SIZE_GCM, ciphertext, 0, ciphertext.length);

        KeyParameter keyParameter = new KeyParameter(key);
        AEADParameters parameters = new AEADParameters(keyParameter, GCM_MODE_MAC_SIZE_BITS, nonce);
        cipher.init(false, parameters);

        int maxOutputSize = cipher.getOutputSize(ciphertext.length);
        byte[] plaintextBytes = new byte[maxOutputSize];

        int decipheredBytesSize = cipher.processBytes(ciphertext, 0, ciphertext.length, plaintextBytes, 0);
        cipher.doFinal(plaintextBytes, decipheredBytesSize);

        String plaintext;
        try {
            plaintext = new String(plaintextBytes, "utf-8");
        } catch (UnsupportedEncodingException e) {
            plaintext = new String(plaintextBytes);
        }

        return plaintext;
    }

    public static String decipherInCBCMode(byte[] ciphertextBytesWithIV, byte[] key, BlockCipher engine, int ivSize) throws InvalidCipherTextException {
        BlockCipher cipherInOperationMode = new CBCBlockCipher(engine);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cipherInOperationMode, new PKCS7Padding());

        // Extract the IV
        byte[] iv = new byte[ivSize];
        byte[] ciphertextBytes = new byte[ciphertextBytesWithIV.length - ivSize];
        System.arraycopy(ciphertextBytesWithIV, 0, iv, 0, ivSize);
        System.arraycopy(ciphertextBytesWithIV, ivSize, ciphertextBytes, 0, ciphertextBytesWithIV.length - ivSize);

        ParametersWithIV cipherInitParams = new ParametersWithIV(new KeyParameter(key), iv);
        cipher.init(false, cipherInitParams);

        int maxOutputSize = cipher.getOutputSize(ciphertextBytes.length);
        byte[] plaintextBytes = new byte[maxOutputSize];

        int finalOutputSize = cipher.processBytes(ciphertextBytes, 0, ciphertextBytes.length, plaintextBytes, 0);
        finalOutputSize += cipher.doFinal(plaintextBytes, finalOutputSize);

        // remove padding
        byte[] unpaddedPlaintextBytes = new byte[finalOutputSize];
        System.arraycopy(plaintextBytes, 0, unpaddedPlaintextBytes, 0, finalOutputSize);

        String plaintext;
        try {
            plaintext = new String(unpaddedPlaintextBytes, "utf-8");
        } catch (UnsupportedEncodingException e) {
            plaintext = new String(unpaddedPlaintextBytes);
        }

        return plaintext;
    }
}
