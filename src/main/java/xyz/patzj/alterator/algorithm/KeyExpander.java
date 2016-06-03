package xyz.patzj.alterator.algorithm;

/**
 * Key expansion abstract class.
 * @author patzj
 */
public abstract class KeyExpander {
    private String key;
    public abstract void expandKey() throws Exception;
    public abstract int[][] getSubKey(int round);

    public KeyExpander() { }

    /**
     * Constructor with the private key as parameter.
     * @param key Private key for key expansion.
     */
    public KeyExpander(String key) {
        setKey(key);
    }

    /**
     * Return private key.
     * @return Private key.
     */
    public String getKey() {
        return key;
    }

    /**
     * Set private key.
     * @param key Private key for key expansion.
     */
    public void setKey(String key) {
        this.key = key;
    }
}
