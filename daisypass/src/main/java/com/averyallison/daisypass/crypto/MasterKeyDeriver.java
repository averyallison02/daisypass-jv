package com.averyallison.daisypass.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives a key from a user-entered Master Password
 * <ul>
 *  <li><code>masterPassword</code> - A plaintext master password received at runtime from the user</li>
 *  <li><code>saltB64</code> - A Base64-encoded salt to make the password unique<li>
 *  <li><code>DEFAULT_SALT_LENGTH</code> - default length for the public salt in bytes</li>
 *  <li><code>ITERATION_COUNT</code> - number of times to run password and salt through the algorithm</li>
 *  <li><code>KEYLENGTH</code> - length of the derived key in bytes</li>
 *  <li><code>DERIVER_ALGORITHM</code> - algorithm for the key deriver to use</li>
 * </ul>
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class MasterKeyDeriver 
{
    private String masterPassword;
    private String saltB64;

    public static final int DEFAULT_SALT_LENGTH = 16; 
    public static final int ITERATION_COUNT = 100_000;
    public static final int KEY_LENGTH = 256;

    private final String DERIVER_ALGORITHM = "PBKDF2WithHmacSHA256";

    public String getMasterPassword()
    {
        return this.masterPassword;
    }

    /**
     * ensures the following about an entered master password:
     * <ul>
     *  <li>It contains between twelve and twenty characters</li>
     *  <li>It contains at least one number (0-9)</li>
     *  <li>It contains at least one character that is not a letter or number</li>
     *  <li>It does not contain whitespace or emojis</li>
     * </ul>
     * @param masterPassword The password to be validated
     * @return The validity of the password
     */
    private boolean validateMasterPassword(String masterPassword)
    {
        if (20 < masterPassword.length() || masterPassword.length() < 12) return false;

        boolean containsDigit = false;
        boolean containsSpecial = false;
        for (int i = 0; i < masterPassword.length(); i++) 
        {
            char c = masterPassword.charAt(i);
            if (Character.isWhitespace(c)) return false;
            if (Character.isEmoji(c)) return false;

            if (Character.isDigit(c)) containsDigit = true;
            if (!(Character.isLetterOrDigit(c))) containsSpecial = true;
        }

        if (!containsDigit) return false;
        if (!containsSpecial) return false;

        return true;
    }

    public boolean setMasterPassword(String masterPassword)
    {
        masterPassword = masterPassword.trim();

        if (!(validateMasterPassword(masterPassword)))
        {
            return false;
        }

        this.masterPassword = masterPassword;
        return true;
    }

    public String getSaltB64()
    {
        return this.saltB64;
    }

    public void setSaltB64(String saltB64)
    {
        this.saltB64 = saltB64;
    }

    /**
     * generates a Base64 representation of a random salt
     * @param length the length of the decoded salt, in bytes
     * @return the encoded salt
     */
    public String generateSalt(int length)
    {
        SecureRandom salter = new SecureRandom();
        byte[] salt = new byte[length];

        salter.nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    public String generateSalt()
    {
        return generateSalt(DEFAULT_SALT_LENGTH);
    }

    /**
     * derive a key from the master password and salt fields
     * @return the resulting key
     * @throws NoSuchAlgorithmException DERIVER_ALGORITHM is invalid
     * @throws InvalidKeySpecException keySpec could not be created from password or salt
     */
    public SecretKey deriveKey() throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PBEKeySpec keySpec = new PBEKeySpec(
            this.masterPassword.toCharArray(), 
            Base64.getDecoder().decode(saltB64), 
            ITERATION_COUNT, 
            KEY_LENGTH);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DERIVER_ALGORITHM);
        return keyFactory.generateSecret(keySpec);
    }
}
