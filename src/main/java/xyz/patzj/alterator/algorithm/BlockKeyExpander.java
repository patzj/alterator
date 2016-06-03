package xyz.patzj.alterator.algorithm;

import xyz.patzj.alterator.algorithm.KeyExpander;

/**
 * @author patzj
 */
public abstract class BlockKeyExpander extends KeyExpander {
    private int subKey[][][] = new int[11][4][4]; // round 0 to 10 of 128-bit block

    /**
     * Returns the subkey of the specified round.
     * @param round Current encryption or decryption round.
     * @return Subkey for specific encryption or decryption round.
     * @throws IndexOutOfBoundsException
     */
    public int[][] getSubKey(int round) throws IndexOutOfBoundsException {
        return subKey[round];
    }
}
