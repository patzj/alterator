package xyz.patzj.alterator;

import xyz.patzj.alterator.algorithm.BlockSymmetricCipher;
import xyz.patzj.alterator.algorithm.aes.AESCore;

/**
 * @author patzj
 */
public class Alterator {
    public static final int AES = 1;

    public static BlockSymmetricCipher getInstance (int algorithm)
            throws AlgorithmNotFoundException {
        BlockSymmetricCipher cipher;

        switch(algorithm) {
            case 1:
                cipher = createAESInstance();
                break;
            default:
                throw new AlgorithmNotFoundException();
        }

        return cipher;
    }

    private static AESCore createAESInstance() {
        return new AESCore();
    }
}
