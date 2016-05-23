package xyz.patzj.alterator.algorithm;

/**
 * Symmetric Cipher abstract class.
 * @author patzj
 */
@SuppressWarnings("unused")
public abstract class SymmetricCipher implements Cipher {
    private String plainText;
    private String cipherText;
    private String key;

    public SymmetricCipher() { }

    /**
     *
     * @param plainText Plaintext to be encrypted.
     * @param key Private key for encryption and decryption.
     */
    public SymmetricCipher(String plainText, String key) {
        setPlainText(plainText);
        setKey(key);
    }

    /**
     *
     * @return Plaintext.
     */
    public String getPlainText() {
        return plainText;
    }

    /**
     *
     * @param plainText Plaintext to be encrypted.
     */
    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    /**
     *
     * @return Ciphertext.
     */
    public String getCipherText() {
        return cipherText;
    }

    /**
     *
     * @param cipherText Ciphertext to be decrypted
     */
    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    /**
     *
     * @return Private key.
     */
    public String getKey() {
        return key;
    }

    /**
     *
     * @param key Private Key for encryption and decryption.
     */
    public void setKey(String key) {
        this.key = key;
    }
}
