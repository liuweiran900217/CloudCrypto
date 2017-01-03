package cn.edu.buaa.crypto.algebra.generators;

import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Helper for finding a pair of prime BigInteger's {p, q; p = 2q + 1}
 */
class SecurePrimeParametersGeneratorHelper {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /*
     * Finds a pair of prime BigInteger's {p, q: p = 2q + 1}
     *
     * (see: Handbook of Applied Cryptography 4.86)
     */
    static BigInteger[] generateSafePrimes(int size, int certainty, SecureRandom random) {
        BigInteger p, q;
        int qLength = size - 1;

        for (; ; ) {
            q = BigInteger.probablePrime(qLength, random);
            p = q.shiftLeft(1).add(ONE);
            if (p.isProbablePrime(certainty) && (certainty <= 2 || q.isProbablePrime(certainty))) {
                break;
            }
        }

        return new BigInteger[]{p, q};
    }

    static BigInteger selectGenerator(BigInteger p, SecureRandom random) {
        BigInteger pMinusTwo = p.subtract(TWO);
        BigInteger g;

			/*
             * RFC 2631 2.2.1.2 (and see: Handbook of Applied Cryptography 4.81)
			 */
        do {
            BigInteger h = BigIntegers.createRandomInRange(TWO, pMinusTwo, random);

            g = h.modPow(TWO, p);
        } while (g.equals(ONE));

        return g;
    }
}
