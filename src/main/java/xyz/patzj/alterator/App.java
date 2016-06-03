package xyz.patzj.alterator;

import xyz.patzj.alterator.algorithm.BlockSymmetricCipher;
import xyz.patzj.alterator.algorithm.aes.AESKeyExpander;

import java.util.logging.Logger;

public class App {
    public static final Logger LOGGER
            = Logger.getLogger(App.class.getName());

    public static void main(String[] args) {
        String key = "Thats my Kung Fu";
        String pt = "Two One Nine Two";
        BlockSymmetricCipher cipher = null;
        long start, end;

        start = System.currentTimeMillis();
        try {
            cipher = Alterator.getInstance(Alterator.AES);
        } catch(AlgorithmNotFoundException e) {
            LOGGER.severe(e.getMessage());
        }

        cipher.setPlainText(pt);
        cipher.setKey(key);
        cipher.setKeyExpander(new AESKeyExpander(cipher.getKey()));
        cipher.encrypt();
        end = System.currentTimeMillis();
        System.out.println(cipher.getCipherText());
        System.out.println("in " + (end - start) + "ms");
    }
}
