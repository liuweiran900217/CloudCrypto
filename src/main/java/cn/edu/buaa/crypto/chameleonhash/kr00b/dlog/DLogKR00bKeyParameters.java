package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin Chameleon hash key parameters
 */
class DLogKR00bKeyParameters extends AsymmetricKeyParameter {
    private SecurePrimeSerParameter params;

    DLogKR00bKeyParameters(boolean isPrivate, SecurePrimeSerParameter params) {
        super(isPrivate);
        this.params = params;
    }

    public SecurePrimeSerParameter getParameters() {
        return params;
    }
}