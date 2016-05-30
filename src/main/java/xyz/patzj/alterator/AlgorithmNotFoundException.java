package xyz.patzj.alterator;

/**
 * @author patzj
 */
public class AlgorithmNotFoundException extends Exception {
    public AlgorithmNotFoundException() {
        super("No algorithm implementation found.");
    }
}
