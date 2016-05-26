package xyz.patzj.alterator.algorithm.aes;

import java.util.Arrays;

import static xyz.patzj.alterator.algorithm.aes.AESConstants.*;

/**
 * AES Algorithm key expansion schedule.
 * @author patzj
 */
public class AESKeyExpansion {
    private String key;
    private int subKey[][][] = new int[11][4][4]; // round 0 to 10 of 128-bit block
    private int round;
    private int row;
    private final int REQ_KEY_SIZE = 16; // required key size
    private final int MAX_PROC_SIZE = 4; // max number of bytes for processing
    private final int MAX_ROUND = 10; // max key schedule round

    public AESKeyExpansion() { }

    /**
     *
     * @param key Private key for key expansion.
     */
    public AESKeyExpansion(String key) {
        setKey(key);
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
     * @param key Private key for key expansion.
     */
    public void setKey(String key) {
        this.key = key;
    }

    /**
     *
     * @param round Current AES encryption or decryption round.
     * @return Subkey for specific AES encryption or decryption round.
     * @throws IndexOutOfBoundsException
     */
    public int[][] getSubKey(int round) throws IndexOutOfBoundsException {
        return subKey[round];
    }

    /**
     *
     * @throws Exception
     */
    public void expandKey() throws Exception {
        byte[] keyInHex;
        int keyPadding;
        int keySize = key.length();
        int counter = 0;
        StringBuilder tmpKey = new StringBuilder(key);

        if(keySize > REQ_KEY_SIZE)
            throw new Exception();

        // PKCS7 padding
        if(keySize < REQ_KEY_SIZE) {
            keyPadding = REQ_KEY_SIZE - keySize;

            for(int i = 0; i < keyPadding; i++)
                tmpKey.append((char) keyPadding);
        }

        keyInHex = tmpKey.toString().getBytes();

        // assign to subKey 0
        for(int x = 0; x < MAX_PROC_SIZE; x++) {
            for(int y = 0; y < MAX_PROC_SIZE; y++) {
                subKey[0][x][y] = keyInHex[counter];
                counter++;
            }
        }

        round = 1; // initialize round for processing
        while(round <= MAX_ROUND) {
            int prev = round - 1;
            int[] tmp = Arrays.copyOf(subKey[prev][3], 4); // get 4th row of previous subKey

            doCircularLeftShift(tmp);
            doSubBytes(tmp);
            doXorRcon(tmp, prev);

            row = 0; // initialize or reinitialize row for processing
            while (row < MAX_PROC_SIZE) {
                tmp[0] ^= subKey[prev][row][0];
                subKey[round][row][0] = tmp[0]; // assign byte to current round subKey

                // xor with previous round  key
                for (int j = 1; j < MAX_PROC_SIZE; j++) {
                    tmp[j] ^= subKey[prev][row][j];
                    subKey[round][row][j] = tmp[j]; // assign byte to current round subKey
                }
                row++;
            }
            round++;
        }
    }

    // circular byte left shift
    private void doCircularLeftShift(int[] data) {
        int tmp = data[0];
        for(int i = 0; i < MAX_PROC_SIZE; i++) {
            if(i == 3)
                data[i] = tmp;
            else
                data[i] = data[i + 1];
        }
    }

    // byte substitution
    private void doSubBytes(int[] data) {
        int x, y;
        String byteInHex;
        for(int i = 0; i < MAX_PROC_SIZE; i++) {
            byteInHex = Integer.toHexString(data[i]);
            if(byteInHex.length() < 2) {
                x = 0;
                y = Integer.parseInt(byteInHex, 16);
            } else {
                x = Integer.parseInt(byteInHex.substring(0, 1), 16);
                y = Integer.parseInt(byteInHex.substring(1), 16);
            }

            data[i] = S_BOX[x][y];
        }
    }

    // xor with round constants
    private void doXorRcon(int[] data, int round) {
        for(int i = 0; i < MAX_PROC_SIZE; i++) {
            data[i] = data[i] ^ R_CON[round][i];
        }
    }
}
