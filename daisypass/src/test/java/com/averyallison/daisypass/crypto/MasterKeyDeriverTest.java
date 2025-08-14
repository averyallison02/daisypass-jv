package com.averyallison.daisypass.crypto;

import static org.junit.Assert.*;

import java.util.Base64;

import org.junit.Test;

public class MasterKeyDeriverTest 
{
    @Test
    public void duplicatePasswordTest()
    {
       MasterKeyDeriver testDeriver = new MasterKeyDeriver("sdsdvc@$sd34jmd");
       String testDeriverSalt = testDeriver.getSaltB64();

       MasterKeyDeriver testDeriverSamePass = new MasterKeyDeriver("sdsdvc@$sd34jmd");
       String testDeriverSamePassSalt = testDeriverSamePass.getSaltB64();

       assertFalse(testDeriverSalt.equals(testDeriverSamePassSalt));
    }

    @Test
    public void generateSaltTest()
    {
        MasterKeyDeriver testDeriver = new MasterKeyDeriver("TestPassword");

       String saltB64 = testDeriver.generateSalt();
       byte[] salt = Base64.getDecoder().decode(saltB64);
       assertTrue(salt.length == MasterKeyDeriver.DEFAULT_SALT_LENGTH);

       String oldSaltB64 = saltB64;
       saltB64 = testDeriver.generateSalt();
       salt = Base64.getDecoder().decode(saltB64);
       assertTrue(oldSaltB64 != saltB64);

       saltB64 = testDeriver.generateSalt(8);
       salt = Base64.getDecoder().decode(saltB64);
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
