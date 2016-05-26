package xyz.patzj.alterator;

import xyz.patzj.alterator.algorithm.aes.AESKeyExpansion;

/**
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) {
        String key = "Thats my Kung Fu";
        AESKeyExpansion keyExpansion = new AESKeyExpansion(key);
        try {
            keyExpansion.expandKey();
        } catch(Exception e) {
            e.printStackTrace();
        }

        for(int w = 0; w <= 10; w++) {
            int[][] subkey = keyExpansion.getSubKey(w);

            for (int x = 0; x < 4; x++) {
                for (int y = 0; y < 4; y++) {
                    System.out.print(Integer.toHexString(subkey[x][y]) + "\t");
                }
            }
            System.out.println();
        }
    }
}
