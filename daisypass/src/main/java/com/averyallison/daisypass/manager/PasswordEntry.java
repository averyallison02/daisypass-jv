package com.averyallison.daisypass.manager;

import java.util.Arrays;

import java.util.Base64;

/**
 * Stores data for a password entry
 * <ul>
 *  <li><code>encryptedPasswordData</code> - encrypted data associated with this password</li>
 *  <li><code>nickname</code> - a short name used to search for a password</li>
 *  <li><code>url</code> - (optional) the website url associated with this password</li>
 *  <li><code>username</code> - (optional) the username or e-mail associated with this password</li>
 *  <li><code>notes</code> - (optional) additional data associated with this password</li>
 * </ul>
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class PasswordEntry 
{
    /**
     * Stores encrypted data of a password entry
     * <ul>
     *  <li><code>encryptedPassword</code> - a password encrypted by a master key</li>
     *  <li><code>iv</code> - a public iv for decrypting a password</li>
     * </ul>
     */
    public static final class EncryptedPasswordData implements Cloneable
    {
        private byte[] encryptedPassword;
        private byte[] iv;

        public EncryptedPasswordData(byte[] encryptedPassword, byte[] iv)
        {
            setEncryptedPassword(encryptedPassword);
            setIV(iv);
        }

        public byte[] getEncryptedPassword()
        {
            return this.encryptedPassword.clone();
        }
            
        public void setEncryptedPassword(byte[] encryptedPassword)
        {
            this.encryptedPassword = encryptedPassword.clone();
        }

        public String getEncryptedPasswordB64()
        {
            return Base64.getEncoder().encodeToString(this.encryptedPassword);
        }

        public void setEncryptedPasswordB64(String encryptedPasswordB64)
        {
            this.encryptedPassword = Base64.getDecoder().decode(encryptedPasswordB64);
        }

        public byte[] getIV()
        {
           return this.iv.clone();
        }

        public void setIV(byte[] iv)
        {
            this.iv = iv.clone();
        }

        public String getIVB64()
        {
            return Base64.getEncoder().encodeToString(this.iv);
        }

        public void setIVB64(String ivB64)
        {
            this.iv = Base64.getDecoder().decode(ivB64);
        }

        @Override
        public EncryptedPasswordData clone()
        {
            return new EncryptedPasswordData(this.encryptedPassword, this.iv);
        }

        @Override
        public final int hashCode()
        {
            return this.encryptedPassword.hashCode() + this.iv.hashCode();
        }

        @Override
        public final boolean equals(Object other)
        {
            if (!(other instanceof EncryptedPasswordData)) return false;

            EncryptedPasswordData otherPasswordData = (EncryptedPasswordData) other;
            return Arrays.equals(this.encryptedPassword, otherPasswordData.encryptedPassword) && Arrays.equals(this.iv, otherPasswordData.iv);
        }
    }

    private EncryptedPasswordData encryptedPasswordData;

    private String nickname;
    private String url;
    private String username;
    private String notes;

    public PasswordEntry(EncryptedPasswordData encryptedPasswordData)
    {
        setEncryptedPasswordData(encryptedPasswordData);        
    }

    public EncryptedPasswordData getEncryptedPasswordData()
    {
        return this.encryptedPasswordData.clone();
    }

    public void setEncryptedPasswordData(EncryptedPasswordData encryptedPasswordData)
    {
        this.encryptedPasswordData = encryptedPasswordData.clone();
    }

    public String getNickname()
    {
        return this.nickname;
    }

    public void setNickname(String nickname)
    {
        this.nickname = nickname;
    }

    public String getURL()
    {
        return this.url;
    }

    public void setURL(String url)
    {
        this.url = url;
    }

    public String getUsername()
    {
        return this.username;
    }

    public void setUsername(String username)
    {
        this.username = username;
    }

    public String getNotes()
    {
        return this.notes;
    }

    public void setNotes(String notes)
    {
        this.notes = notes;
    }
}
