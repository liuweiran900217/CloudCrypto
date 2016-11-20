package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Asymmetric key serializable parameter.
 */
public class AsymmetricKeySerParameter implements CipherParameters, java.io.Serializable {
    private boolean privateKey;

    public AsymmetricKeySerParameter(boolean privateKey) {
        this.privateKey = privateKey;
    }

    public boolean isPrivate()
    {
        return privateKey;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof AsymmetricKeySerParameter) {
            AsymmetricKeySerParameter that = (AsymmetricKeySerParameter)anOjbect;
            //Compare Pairing Parameters
            return (this.privateKey == that.privateKey);
        }
        return false;
    }
}
