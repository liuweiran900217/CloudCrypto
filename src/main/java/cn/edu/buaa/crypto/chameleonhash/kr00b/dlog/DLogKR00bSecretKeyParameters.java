package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin secret key parameters
 */
class DLogKR00bSecretKeyParameters extends DLogKR00bKeyParameters {
    private BigInteger x;

    DLogKR00bSecretKeyParameters(BigInteger x, SecurePrimeSerParameter params) {
        super(true, params);
        this.x = x;
    }

    public BigInteger getX() {
        return x;
    }
}