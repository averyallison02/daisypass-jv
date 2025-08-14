package com.averyallison.daisypass.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;

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

    public static final String DERIVER_ALGORITHM = "PBKDF2WithHmacSHA256";

    /**
     * Initialize the key deriver with a stored salt
     * @param masterPassword a 12-20 character user-entered string
     * @param saltB64 a salt pulled from persistent storage
     */
    public MasterKeyDeriver(String masterPassword, String saltB64)
    {
        this.masterPassword = masterPassword;
        this.saltB64 = saltB64;
    }

    /**
     * Initialize the key deriver with a generated salt
     * @param masterPassword a 12-20 character user-entered string
     */
    public MasterKeyDeriver(String masterPassword)
    {
        this.masterPassword = masterPassword;
        this.saltB64 = generateSalt();
    }

    public String getMasterPassword()
    {
        return this.masterPassword;
    }

    /**
     * ensures the following about an entered master password:
     * <ul>
     *  <li>it contains between twelve and twenty characters</li>
     *  <li>it contains at least one letter</li>
     *  <li>it contains at least one number (0-9)</li>
     *  <li>it contains at least one special character from the set of:
     *      <code>! @ # $ % ^ & * ( ) _ + - = [ ] { } | ; : , . &lt; &gt; ? /</code>
     *  </li>
     *  <li>it does not contain whitespace or emojis</li>
     * </ul>
     * @param masterPassword The password to be validated
     * @return true if the password meets all criteria, false otherwise.
     */
    private boolean validateMasterPassword(String masterPassword)
    {
        final int MAX_LENGTH = 20;
        final int MIN_LENGTH = 12;

        if (MAX_LENGTH < masterPassword.length() || masterPassword.length() < MIN_LENGTH) return false;

        final String PATTERN_LETTERS = ".*[A-Za-z].*";
        final String PATTERN_DIGITS = ".*[0-9].*";
        final String PATTERN_SPECIALS = ".*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/].*";
        final String PATTERN_ALLOWED = "^[A-Za-z0-9!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?/]+$";

        return masterPassword.matches(PATTERN_LETTERS) &&
            masterPassword.matches(PATTERN_DIGITS) &&
            masterPassword.matches(PATTERN_SPECIALS) &&
            masterPassword.matches(PATTERN_ALLOWED);
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
