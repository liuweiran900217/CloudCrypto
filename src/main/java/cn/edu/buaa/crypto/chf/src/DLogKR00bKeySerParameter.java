package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.SecurePrimeSerParameter;

/**
 * Created by Weiran Liu on 2016/10/19.
 *
 * Krawczyk-Rabin Chameleon hash key parameters
 */
public class DLogKR00bKeySerParameter extends AsymmetricKeySerParameter {
    private SecurePrimeSerParameter params;

    DLogKR00bKeySerParameter(boolean isPrivate, SecurePrimeSerParameter params) {
        super(isPrivate);
        this.params = params;
    }

    public SecurePrimeSerParameter getParameters() {
        return params;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof DLogKR00bKeySerParameter) {
            DLogKR00bKeySerParameter that = (DLogKR00bKeySerParameter)anOjbect;
            //Compare SecurePrimeSerParameter
            return this.getParameters().equals(that.getParameters());
        }
        return false;
    }
}