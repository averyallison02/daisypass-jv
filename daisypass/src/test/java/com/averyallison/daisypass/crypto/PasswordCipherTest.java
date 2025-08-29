package com.averyallison.daisypass.crypto;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Arrays;

import com.averyallison.daisypass.manager.PasswordEntry.EncryptedPasswordData;

import java.security.GeneralSecurityException;

public class PasswordCipherTest 
{
    @Test
    public void initCipherTest() throws GeneralSecurityException
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("abcde123456@");
        new PasswordCipher(testDeriver.deriveKey());
    }

    @Test(expected=IllegalArgumentException.class)
    public void initCipherNullTest()
    {
        new PasswordCipher(null);
    }

    @Test
    public void encryptPasswordDuplicateTest() throws GeneralSecurityException
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("abcde123456@");
        PasswordCipher testCipher = new PasswordCipher(testDeriver.deriveKey());

        EncryptedPasswordData encryptedPasswordData = testCipher.encryptPassword("TestPassword");
        EncryptedPasswordData duplicateEncryptedPasswordData = testCipher.encryptPassword("TestPassword");

        assertFalse(Arrays.equals(encryptedPasswordData.getEncryptedPassword(), duplicateEncryptedPasswordData.getEncryptedPassword()));
        assertFalse(Arrays.equals(encryptedPasswordData.getIV(), duplicateEncryptedPasswordData.getIV()));
    }

    @Test
    public void encryptDecryptPasswordTest() throws GeneralSecurityException
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("abcde123456@");
        PasswordCipher testCipher = new PasswordCipher(testDeriver.deriveKey());

        String testPassword = "TestPassword";
        EncryptedPasswordData testPasswordEncrypted = testCipher.encryptPassword(testPassword);

        assertEquals(testCipher.decryptPassword(testPasswordEncrypted), testPassword);
    }
}
