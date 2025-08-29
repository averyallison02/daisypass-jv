package com.averyallison.daisypass.crypto;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Arrays;

import java.security.GeneralSecurityException;

public class MasterKeyDeriverTest 
{
    @Test
    public void duplicatePasswordTest() throws GeneralSecurityException
    {
        final String DUPLICATE_PASSWORD = "sdsdvc@$sd34jmd";

       MasterKeyDeriver testDeriver = new MasterKeyDeriver(DUPLICATE_PASSWORD);
       byte[] testDeriverSalt = testDeriver.getSalt();

       MasterKeyDeriver testDeriverSamePass = new MasterKeyDeriver(DUPLICATE_PASSWORD);
       byte[] testDeriverSamePassSalt = testDeriverSamePass.getSalt();

       assertFalse(testDeriverSalt.equals(testDeriverSamePassSalt));

       byte[] passKey = testDeriver.deriveKey().getEncoded();
       byte[] samePassKey = testDeriverSamePass.deriveKey().getEncoded();
       assertFalse(Arrays.equals(passKey, samePassKey));
    }

    @Test
    public void generateSaltTest()
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("TestPassword");

       byte[] salt = testDeriver.generateSalt();
       assertTrue(salt.length == 16);

       byte[] oldSalt = salt.clone();
       salt = testDeriver.generateSalt();
       assertTrue(oldSalt != salt);

       salt = testDeriver.generateSalt(8);
       assertTrue(salt.length == 8);
    }

    @Test
    public void validateMasterPasswordTest()
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("TestPassword");

        assertFalse(testDeriver.setMasterPassword(""));
        assertFalse(testDeriver.setMasterPassword("abcdefghij@1234567890"));
        assertFalse(testDeriver.setMasterPassword("abc123@"));
        assertFalse(testDeriver.setMasterPassword("abcdefghij@12 3"));

        assertTrue(testDeriver.setMasterPassword("  abcdefghij@123456789  "));
        assertTrue(testDeriver.setMasterPassword("abcde123456@"));
        assertTrue(testDeriver.setMasterPassword("@325642asc!#"));
    }
}
