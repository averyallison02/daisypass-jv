package com.averyallison.daisypass.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import javax.crypto.spec.IvParameterSpec;

import com.averyallison.daisypass.manager.PasswordEntry.EncryptedPasswordData;

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

    private static final String DEFAULT_TRANSFORMATION = "AES/CBC/PKCS5Padding";

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
     * generate a SecureRandom IV spec
     * @return the generated spec
     */
    private IvParameterSpec generateIV()
    {
        final int AES_BLOCK_SIZE = 16;

        byte[] iv = new byte[AES_BLOCK_SIZE];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * takes a password and encrypts with passwordKey
     * @param password a plain-text password
     * @return a byte array containing the encrypted password
     * @throws GeneralSecurityException cipher had issues with transformation or encryption
     */
    public EncryptedPasswordData encryptPassword(String password) throws GeneralSecurityException 
    {
        Cipher encryptCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
        IvParameterSpec ivParam = generateIV();
        encryptCipher.init(Cipher.ENCRYPT_MODE, passwordKey, ivParam);

        byte[] encryptedPassword = encryptCipher.doFinal(password.getBytes());
        byte[] iv = ivParam.getIV();
        return new EncryptedPasswordData(encryptedPassword, iv);
    }

    /**
     * takes an encrypted password and decrypts with passwordKey
     * @param encryptedPasswordData a structure containing an encrypted password and an IV
     * @return a plain-text password
     * @throws GeneralSecurityException cipher had issues with transformation or decryption
     */
    public String decryptPassword(EncryptedPasswordData encryptedPasswordData) throws GeneralSecurityException
    {
        Cipher decryptCipher = Cipher.getInstance(DEFAULT_TRANSFORMATION);
        decryptCipher.init(Cipher.DECRYPT_MODE, passwordKey, new IvParameterSpec(encryptedPasswordData.getIV()));

        byte[] decryptedPassword = decryptCipher.doFinal(encryptedPasswordData.getEncryptedPassword());
        return new String(decryptedPassword);
    }
}
