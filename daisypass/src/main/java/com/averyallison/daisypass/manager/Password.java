package com.averyallison.daisypass.manager;

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
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class Password 
{
    private String encryptedPasswordB64;
    private String nonceB64;

    private String nickname;
    private String url;
    private String username;
    private String notes;

    public String getEncryptedPasswordB64()
    {
        return this.encryptedPasswordB64;
    }

    public void setEncryptedPasswordB64(String encryptedPasswordB64)
    {
        this.encryptedPasswordB64 = encryptedPasswordB64;
    }

    public String getNonceB64()
    {
        return this.nonceB64;
    }

    public void setNonceB64(String nonceB64)
    {
        this.nonceB64 = nonceB64;
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
