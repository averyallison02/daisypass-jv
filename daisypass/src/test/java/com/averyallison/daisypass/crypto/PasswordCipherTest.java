package com.averyallison.daisypass.crypto;

import static org.junit.Assert.*;
import org.junit.Test;

import com.averyallison.daisypass.manager.Password.EncryptedPasswordData;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

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
    public void encryptPasswordTest() throws GeneralSecurityException
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("abcde123456@");
        PasswordCipher testCipher = new PasswordCipher(testDeriver.deriveKey());

        EncryptedPasswordData encryptedPasswordData = testCipher.encryptPassword("TestPassword");
    }
}
