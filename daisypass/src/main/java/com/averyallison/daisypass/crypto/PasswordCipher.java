package com.averyallison.daisypass.crypto;

import java.util.Base64;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Utility for encrypting and decrypting passwords
 * <ul>
 *  <li><code>passwordKey</code> - The SecretKey this PasswordCipher will use for encryption and decryption
 *  <li><code>DEFAULT_TRANSFORMATION</code> - The default transformation from the password ciphers to use.
 * </ul>
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class PasswordCipher 
{
    private SecretKey passwordKey;

    private static final String DEFAULT_TRANSFORMATION = "AES";

    public PasswordCipher(SecretKey passwordKey)
    {
        this.setPasswordKey(passwordKey);
    }

    public SecretKey getPasswordKey()
    {
        return this.passwordKey;
    }

    public void setPasswordKey(SecretKey passwordKey)
    {
        if (passwordKey == null) throw new IllegalArgumentException("passwordKey cannot be null");
        this.passwordKey = passwordKey;
    }

    /**
     * takes a password and encrypts with passwordKey
     * @param password a plain-text password
     * @return a Base64 representation of the encrypted password
     * @throws GeneralSecurityException cipher had issues with transformation or encryption
     */
    public String encryptPassword(String password) throws GeneralSecurityException 
    {
        Cipher encryptCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
        encryptCipher.init(Cipher.ENCRYPT_MODE, passwordKey);

        byte[] encryptedPassword = encryptCipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }

    /**
     * takes an encrypted password and decrypts with passwordKey
     * @param encryptedPasswordB64 an encrypted password encoded in Base64
     * @return a plain-text password
     * @throws GeneralSecurityException cipher had issues with transformation or decryption
     */
    public String decryptPassword(String encryptedPasswordB64) throws GeneralSecurityException
    {
        byte[] encryptedPassword = Base64.getDecoder().decode(encryptedPasswordB64);

        Cipher decryptCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
        decryptCipher.init(Cipher.DECRYPT_MODE, passwordKey);

        byte[] decryptedPassword = decryptCipher.doFinal(encryptedPassword);
        return new String(decryptedPassword);
    }
}
