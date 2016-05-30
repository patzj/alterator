package xyz.patzj.alterator.algorithm;

/**
 * Symmetric Cipher abstract class.
 * @author patzj
 */
public abstract class SymmetricCipher implements Cipher {
    private String plainText;
    private String cipherText;
    private String key;

    public SymmetricCipher() { }

    /**
     * Set plaintext.
     * @return Plaintext.
     */
    public String getPlainText() {
        return plainText;
    }

    /**
     * Return plaintext.
     * @param plainText Plaintext to be encrypted.
     */
    public void setPlainText(String plainText) {
        this.plainText = plainText;
    }

    /**
     * Set ciphertext.
     * @return Ciphertext.
     */
    public String getCipherText() {
        return cipherText;
    }

    /**
     * Return ciphertext.
     * @param cipherText Ciphertext to be decrypted
     */
    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    /**
     * Set private key.
     * @return Private key.
     */
    public String getKey() {
        return key;
    }

    /**
     * Return private key.
     * @param key Private Key for encryption and decryption.
     */
    public void setKey(String key) {
        this.key = key;
    }
}
