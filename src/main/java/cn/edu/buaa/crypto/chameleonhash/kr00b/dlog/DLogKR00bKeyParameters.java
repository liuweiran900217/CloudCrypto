package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.params.SecurePrimeParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin Chameleon hash key parameters
 */
public class DLogKR00bKeyParameters extends AsymmetricKeyParameter {
    private SecurePrimeParameters params;

    public DLogKR00bKeyParameters(boolean isPrivate, SecurePrimeParameters params) {
        super(isPrivate);
        this.params = params;
    }

    public SecurePrimeParameters getParameters() {
        return params;
    }
}