package com.averyallison.daisypass.crypto;

/**
 * Derives a key from a user-entered Master Password
 * <ul>
 *  <li><code>masterPassword</code> - A plaintext master password received at runtime from the user</li>
 *  <li><code>salt</code> - A salt to make the password unique, or null if one has not been generated yet<li>
 * </ul>
 * @author Avery Allison <averymallison@proton.me>
 * @version 0.1.0
 * @since 0.1.0
 */
public class MasterKeyDeriver 
{
    private String masterPassword;
    private String salt;

    public String getMasterPassword()
    {
        return this.masterPassword;
    }

    /**
     * Ensures the following about an entered master password:
     * <ul>
     *  <li>It contains between twelve and twenty characters</li>
     *  <li>It contains at least one number (0-9)</li>
     *  <li>It contains at least one character that is not a letter or number</li>
     *  <li>It does not contain whitespace or emojis</li>
     * </ul>
     * @param masterPassword The password to be validated
     * @return The validity of the password
     */
    private boolean validateMasterPassword(String masterPassword)
    {
        if (20 < masterPassword.length() || masterPassword.length() < 12) return false;

        boolean containsDigit = false;
        boolean containsSpecial = false;
        for (int i = 0; i < masterPassword.length(); i++) 
        {
            char c = masterPassword.charAt(i);
            if (Character.isWhitespace(c)) return false;
            if (Character.isEmoji(c)) return false;

            if (Character.isDigit(c)) containsDigit = true;
            if (!(Character.isLetterOrDigit(c))) containsSpecial = true;
        }

        if (!containsDigit) return false;
        if (!containsSpecial) return false;

        return true;
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

    public String getSalt()
    {
        return this.salt;
    }

    /**
     * Ensures that the entered salt has between 12 and 20 characters.
     * @param salt The salt to be validated
     * @return The validity of the salt
     */
    private boolean validateSalt(String salt)
    {
        if (20 < salt.length() || salt.length() < 12) return false;
        return true;
    }

    public boolean setSalt(String salt)
    {
        if (!(validateSalt(salt)))
        {
            return false;
        }

        this.salt = salt;
        return true;
    }
}
