package xyz.patzj.alterator;

import xyz.patzj.alterator.algorithm.SymmetricCipher;

import java.util.logging.Logger;

public class App {
    public static final Logger LOGGER
            = Logger.getLogger(App.class.getName());

    public static void main(String[] args) {
        String key = "Thats my Kung Fu";
        String pt = "Two One Nine Two";
        SymmetricCipher cipher = null;

        try {
            cipher = Alterator.getInstance(Alterator.AES);
        } catch(AlgorithmNotFoundException e) {
            LOGGER.severe(e.getMessage());
        }

        cipher.setPlainText(pt);
        cipher.setKey(key);
        cipher.encrypt();
        System.out.println(cipher.getCipherText());
    }
}
