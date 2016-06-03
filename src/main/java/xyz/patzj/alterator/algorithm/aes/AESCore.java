package xyz.patzj.alterator.algorithm.aes;

import java.util.Arrays;
import java.util.logging.Logger;
import xyz.patzj.alterator.algorithm.BlockSymmetricCipher;
import static xyz.patzj.alterator.algorithm.aes.AESConstants.*;

/**
 * AES Algorithm core.
 * @author patzj
 */
public class AESCore extends BlockSymmetricCipher {
	private final int MAX_ROUND = 10;
	private static final Logger LOGGER 
		= Logger.getLogger(AESCore.class.getName());

	public AESCore() { }

    /**
     * Performs the encryption algorithm.
     */
    public void encrypt() {
    	String text = getPlainText();
		int round;
        StringBuilder tmp = new StringBuilder();

    	try {
    		getKeyExpander().expandKey();
    	} catch(Exception e) {
    		LOGGER.severe(e.getMessage());
    		System.exit(0);
    	}
    		
    	if(text.length() % REQ_BLOCK_SIZE > 0)
    		text = doPadText(text);
    	
    	initstateMatrix(text.getBytes());
    	doAddRoundKey(0); // round 0

        // round 1 to 9
        round = 1;
        while(round < MAX_ROUND) {
            doSubBytes();

            for (int y = 1; y < REQ_ROW_SIZE; y++) {
                for (int x = 0; x < y; x++) {
                    doCircularLeftShift(y);
                }
            }

            doMixColumns();
            doAddRoundKey(round);
            round++;
        }
        // round 10
        doSubBytes();
        for (int y = 1; y < REQ_ROW_SIZE; y++) {
            for (int x = 0; x < y; x++) {
                doCircularLeftShift(y);
            }
        }
        doAddRoundKey(MAX_ROUND);

        // set to ciphertext
        for(int x = 0; x < REQ_ROW_SIZE; x++) {
            for(int y = 0; y < REQ_ROW_SIZE; y++) {
                tmp.append((char) getStateMatrix()[x][y]);
            }
        }
        setCipherText(tmp.toString());
    }

    public void decrypt() {
        // TODO decryption algorithm
    }

    /**
     * Initialize the 128-bit state matrix with data.
     * @param data Plaintext converted to array of bytes.
     */
    private void initstateMatrix(byte[] data) {
    	int counter = 0;

        setStateMatrix(new int[4][4]);

    	for(int x = 0; x < 4; x++) {
    		for(int y = 0; y < 4; y++) {
    			getStateMatrix()[x][y] = data[counter];
    			counter++;
    		}
    	}
    }

    /**
     * Adds padding to the plaintext using PKCS7 and returns the padded plaintext.
     * @param text Plaintext.
     * @return Padded plaintext.
     */
    private String doPadText(String text) {
    	int padding;
    	int modTextSize = text.length() % REQ_BLOCK_SIZE;
    	StringBuilder tmp = new StringBuilder();
    	
    	padding = REQ_BLOCK_SIZE - modTextSize;
    	
    	for(int i = 0; i < padding; i++)
    		tmp.append((char) padding);
    	
    	return tmp.toString(); 
    }


    /**
     * Performs an exclusive-or operation between the bytes of a 128-bit state 
     * matrix and the subkey.
     * @param round Current round determining the subkey.
     */
    private void doAddRoundKey(int round) {
        for(int x = 0; x < REQ_ROW_SIZE; x++) {
            for(int y = 0; y < REQ_ROW_SIZE; y++) {
                getStateMatrix()[x][y] ^= getKeyExpander().getSubKey(round)[x][y];
            }
        }
    }

    /**
     * Performs a substitution of bytes using the AES S-Box.
     */
    private void doSubBytes() {
        int x, y;
        String byteInHex;

        for(int i = 0; i < REQ_ROW_SIZE; i++) {
            for(int j = 0; j < REQ_ROW_SIZE; j++) {
                byteInHex = Integer.toHexString(getStateMatrix()[i][j]);
                if(byteInHex.length() > 1) {
                    x = Integer.parseInt(byteInHex.substring(0, 1), 16);
                    y = Integer.parseInt(byteInHex.substring(1), 16);
                } else {
                    x = 0;
                    y = Integer.parseInt(byteInHex, 16);
                }

                getStateMatrix()[i][j] = S_BOX[x][y];
            }
        }
    }

    /**
     * Performs an 8-bit circular left shift to a certain column of the 128-bit 
     * state matrix.
     * @param col Column (y) from the 128-bit state matrix.
     */
    private void doCircularLeftShift(int col) {
        int tmp = getStateMatrix()[0][col];
        for(int i = 0; i < REQ_ROW_SIZE; i++) {
            if(i == 3)
                getStateMatrix()[i][col] = tmp;
            else
                getStateMatrix()[i][col] = getStateMatrix()[i + 1][col];
        }
    }

    /**
     * Performs the multiplication and exclusive-or operations between the 
     * 128-bit block and a fixed matrix.
     */
    private void doMixColumns() {
        int[] tmp;
        int n;

        for(int x = 0; x < REQ_ROW_SIZE; x++) {
            tmp = Arrays.copyOf(getStateMatrix()[x], 4);
            for(int y = 0; y < REQ_ROW_SIZE; y++) {
                n = 0;
                for(int z = 0; z < REQ_ROW_SIZE; z++) {
                    if(FIXED_MATRIX[y][z] == 2)
                        n ^= doFiniteMultiByTwo(tmp[z]);
                    else if(FIXED_MATRIX[y][z] == 3)
                        n ^= doFiniteMultiByThree(tmp[z]);
                    else
                        n ^= tmp[z];
                }

                getStateMatrix()[x][y] = n;
            }
        }
    }

    /**
     * Performs a finite-multiplication by two to the passed byte.
     * @param n Byte from 128-bit state matrix.
     * @return Byte finite-multiplied by two.
     */
    private int doFiniteMultiByTwo(int n) {
        n = n << 1;

        if(n > 0xff)
            n ^= 0x11B;

        return n;
    }

    /**
     * Performs a finite-multiplication by three to the passed byte.
     * @param n Byte from the 128-bit state matrix.
     * @return Byte finite-multiplied by three.
     */
    private int doFiniteMultiByThree(int n) {
        return doFiniteMultiByTwo(n) ^ n;
    }
}
