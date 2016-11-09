package cn.edu.buaa.crypto.algebra.generators;

import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Secure prime parameters {p, q: p = 2q + 1} generator.
 */
public class SecurePrimeParametersGenerator {
    private int size;
    private int certainty;
    private SecureRandom random;

    /**
     * Initialise the parameters generator.
     *
     * @param size      bit length for the prime p
     * @param certainty a measure of the uncertainty that the caller is willing to tolerate:
     *                  the probability that the generated modulus is prime exceeds (1 - 1/2^certainty).
     *                  The execution time of this method is proportional to the value of this parameter.
     * @param random    a source of randomness
     */
    public void init(int size, int certainty, SecureRandom random) {
        this.size = size;
        this.certainty = certainty;
        this.random = random;
    }

    /**
     * which generates the p and g values from the given parameters, returning
     * the CramerShoupParameters object.
     * <p>
     * Note: can take a while...
     * </p>
     */
    public SecurePrimeSerParameter generateParameters() {
        //
        // find a safe prime p where p = 2*q + 1, where p and q are prime.
        //
        BigInteger[] safePrimes = SecurePrimeParametersGeneratorHelper.generateSafePrimes(size, certainty, random);

		BigInteger p = safePrimes[0];
        BigInteger q = safePrimes[1];
        BigInteger g = SecurePrimeParametersGeneratorHelper.selectGenerator(q, random);

        return new SecurePrimeSerParameter(p, q, g);
    }
}
