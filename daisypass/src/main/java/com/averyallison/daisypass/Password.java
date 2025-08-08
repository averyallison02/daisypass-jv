package com.averyallison.daisypass;

/**
 * Stores data for a password entry
 * <ul>
 *  <li><code>encryptedPassword</code> - a password encrypted by a master key</li>
 *  <li><code>nonce</code> - a public nonce for decrypting a password</li>
 *  <li><code>nickname</code> - a short name used to search for a password</li>
 *  <li><code>url</code> - (optional) the website url associated with this password</li>
 *  <li><code>username</code> - (optional) the username or e-mail associated with this password</li>
 *  <li><code>notes</code> - (optional) additional data associated with this password</li>
 * </ul>
 */

public class Password 
{
    private byte[] encryptedPassword;
    private byte[] nonce;

    private String nickname;
    private String url;
    private String username;
    private String notes;

    public byte[] getEncryptedPassword()
    {
        return this.encryptedPassword.clone();
    }

    public void setEncryptedPassword(byte[] encryptedPassword)
    {
        this.encryptedPassword = encryptedPassword.clone();
    }

    public byte[] getNonce()
    {
        return this.nonce.clone();
    }

    public void setNonce(byte[] nonce)
    {
        this.nonce = nonce.clone();
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
