package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.params.SecurePrimeParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin secret key parameters
 */
public class DLogKR00BSecretKeyParameters extends DLogKR00bKeyParameters {
    private BigInteger x;

    public DLogKR00BSecretKeyParameters(BigInteger x, SecurePrimeParameters params) {
        super(true, params);
        this.x = x;
    }

    public BigInteger getX() {
        return x;
    }
}