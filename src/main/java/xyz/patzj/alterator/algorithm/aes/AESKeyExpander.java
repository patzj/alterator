package xyz.patzj.alterator.algorithm.aes;

import java.util.Arrays;
import static xyz.patzj.alterator.algorithm.aes.AESConstants.*;

/**
 * AES Algorithm key expansion schedule.
 * @author patzj
 */
public class AESKeyExpander {
    private String key;
    private int subKey[][][] = new int[11][4][4]; // round 0 to 10 of 128-bit block
    private int round;
    private int row;
    private final int REQ_KEY_SIZE = 16; // required key size
    private final int MAX_ROUND = 10; // max key schedule round

    /**
     * Constructor without parameters.
     */
    public AESKeyExpander() { }

    /**
     * Constructor with the private key as parameter.
     * @param key Private key for key expansion.
     */
    public AESKeyExpander(String key) {
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

    /**
     * Returns the subkey of the specified round.
     * @param round Current AES encryption or decryption round.
     * @return Subkey for specific AES encryption or decryption round.
     * @throws IndexOutOfBoundsException
     */
    public int[][] getSubKey(int round) throws IndexOutOfBoundsException {
        return subKey[round];
    }

    /**
     * Expands the private key into subkeys.
     * @throws Exception
     */
    public void expandKey() throws Exception {
    	byte[] keyInHex;
    	int counter = 0;

        keyInHex = getPaddedKey().getBytes();

        // assign to subkey 0
        for(int x = 0; x < REQ_ROW_SIZE; x++) {
            for(int y = 0; y < REQ_ROW_SIZE; y++) {
                subKey[0][x][y] = keyInHex[counter];
                counter++;
            }
        }

        round = 1; // initialize round for processing
        while(round <= MAX_ROUND) {
            int prev = round - 1;
            int[] tmp = Arrays.copyOf(subKey[prev][3], 4); // get 4th row of previous subkey

            doCircularLeftShift(tmp);
            doSubBytes(tmp);
            doXorRcon(tmp, prev);

            row = 0; // initialize or reinitialize row for processing
            while (row < REQ_ROW_SIZE) {
                tmp[0] ^= subKey[prev][row][0];
                subKey[round][row][0] = tmp[0]; // assign byte to current round subKey

                // xor with previous round  key
                for (int i = 1; i < REQ_ROW_SIZE; i++) {
                    tmp[i] ^= subKey[prev][row][i];
                    subKey[round][row][i] = tmp[i]; // assign byte to current round subKey
                }
                row++;
            }
            round++;
        }
    }
    
    /**
     * Adds padding to the private key using PKCS7 and returns the padded 
     * private key.
     * @return Padded private key.
     * @throws Exception
     */
    private String getPaddedKey() throws Exception {
        int keyPadding;
        int keySize = key.length();
        StringBuilder tmpKey = new StringBuilder(key);

        if(keySize > REQ_KEY_SIZE)
            throw new Exception();

        // PKCS7 padding
        if(keySize < REQ_KEY_SIZE) {
            keyPadding = REQ_KEY_SIZE - keySize;

            for(int i = 0; i < keyPadding; i++)
                tmpKey.append((char) keyPadding);
        }
        
        return tmpKey.toString();
    }

    /**
     * Performs an 8-bit circular left shift to the passed 32-bit row.
     * @param data 32-bit row.
     */
    private void doCircularLeftShift(int[] data) {
        int tmp = data[0];
        for(int i = 0; i < REQ_ROW_SIZE; i++) {
            if(i == 3)
                data[i] = tmp;
            else
                data[i] = data[i + 1];
        }
    }

    /**
     * Performs a substitution of bytes using the AES S-Box.
     * @param data 32-bit row.
     */
    private void doSubBytes(int[] data) {
        int x, y;
        String byteInHex;
        for(int i = 0; i < REQ_ROW_SIZE; i++) {
            byteInHex = Integer.toHexString(data[i]);
            if(byteInHex.length() > 1) {
                x = Integer.parseInt(byteInHex.substring(0, 1), 16);
                y = Integer.parseInt(byteInHex.substring(1), 16);
            } else {
                x = 0;
                y = Integer.parseInt(byteInHex, 16);
            }

            data[i] = S_BOX[x][y];
        }
    }

    /**
     * Performs an exclusive-or operation between the bytes of a 32-bit row and
     * round constants. 
     * @param data 32-bit row,
     * @param round Current round determining the row of round constants.
     */
    private void doXorRcon(int[] data, int round) {
        for(int i = 0; i < REQ_ROW_SIZE; i++) {
            data[i] = data[i] ^ R_CON[round][i];
        }
    }
}
