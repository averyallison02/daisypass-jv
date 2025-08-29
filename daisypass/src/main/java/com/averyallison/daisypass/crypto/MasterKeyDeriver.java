package com.averyallison.daisypass.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.SecureRandom;

import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;

/**
 * Derives a key from a user-entered Master Password
 * <ul>
 *  <li><code>masterPassword</code> - A plaintext master password received at runtime from the user</li>
 *  <li><code>salt</code> - A salt to make the password unique<li>
 *  <li><code>DEFAULT_SALT_LENGTH</code> - default length for the public salt in bytes</li>
 *  <li><code>ITERATION_COUNT</code> - number of times to run password and salt through the algorithm</li>
 *  <li><code>KEYLENGTH</code> - length of the derived key in bytes</li>
 *  <li><code>DERIVER_ALGORITHM</code> - algorithm for the key deriver to use</li>
 *  <li><code>KEY_ALGORITHM</code> - algorithm for converting the PBEKey</li>
 * </ul>
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class MasterKeyDeriver 
{
    private String masterPassword;
    private byte[] salt;

    private static final int DEFAULT_SALT_LENGTH = 16; 
    private static final int ITERATION_COUNT = 100_000;
    private static final int KEY_LENGTH = 256;

    private static final String DERIVER_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String KEY_ALGORITHM = "AES";

    /**
     * Initialize the key deriver with a stored salt
     * @param masterPassword a 12-20 character user-entered string
     * @param saltB64 a Base64-encoded salt pulled from persistent storage
     */
    public MasterKeyDeriver(String masterPassword, String saltB64)
    {
        setMasterPassword(masterPassword);
        setSaltB64(saltB64);
    }

    /**
     * Initialize the key deriver with a generated salt
     * @param masterPassword a 12-20 character user-entered string
     */
    public MasterKeyDeriver(String masterPassword)
    {
        setMasterPassword(masterPassword);
        setSalt(generateSalt());
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

    public byte[] getSalt()
    {
        return this.salt.clone();
    }

    public void setSalt(byte[] salt)
    {
        this.salt = salt.clone();
    }

    public String getSaltB64()
    {
        return Base64.getEncoder().encodeToString(this.salt);
    }

    public void setSaltB64(String saltB64)
    {
        this.salt = Base64.getDecoder().decode(saltB64);
    }

    /**
     * generates a byte[] representation of a random salt
     * @param length the length of the decoded salt, in bytes
     * @return the encoded salt
     */
    public byte[] generateSalt(int length)
    {
        SecureRandom salter = new SecureRandom();
        byte[] salt = new byte[length];

        salter.nextBytes(salt);

        return salt;
    }

    public byte[] generateSalt()
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
            salt, 
            ITERATION_COUNT, 
            KEY_LENGTH);
        
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DERIVER_ALGORITHM);
        byte[] keyBytes = keyFactory.generateSecret(keySpec).getEncoded();

        return new SecretKeySpec(keyBytes, KEY_ALGORITHM);
    }
}
