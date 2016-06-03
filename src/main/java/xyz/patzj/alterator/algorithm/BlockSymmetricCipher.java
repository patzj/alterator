package xyz.patzj.alterator.algorithm;

import xyz.patzj.alterator.algorithm.SymmetricCipher;

import java.security.Key;

/**
 * @author patzj
 */
public abstract class BlockSymmetricCipher extends SymmetricCipher {
    private int[][] stateMatrix;
    private KeyExpander keyExpander;

    /**
     * Returns the n-bit state matrix of data.
     * @return Two-dimensional array of bytes.
     */
    public int[][] getStateMatrix() {
        return stateMatrix;
    }

    /**
     * Sets the n-bits state matrix of data.
     * @param stateMatrix n-bit Two-dimentional array of bytes.
     */
    public void setStateMatrix(int[][] stateMatrix) {
        this.stateMatrix = stateMatrix;
    }

    public KeyExpander getKeyExpander() {
        return keyExpander;
    }

    public void setKeyExpander(KeyExpander keyExpander) {
        this.keyExpander = keyExpander;
    }
}
