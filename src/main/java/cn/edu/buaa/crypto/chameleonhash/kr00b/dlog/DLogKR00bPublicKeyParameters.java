package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.params.SecurePrimeParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin public key parameters
 */
class DLogKR00bPublicKeyParameters extends DLogKR00bKeyParameters {
    private BigInteger y;

    DLogKR00bPublicKeyParameters(BigInteger y, SecurePrimeParameters params) {
        super(false, params);
        this.y = y;
    }

    public BigInteger getY()
    {
        return y;
    }
}
