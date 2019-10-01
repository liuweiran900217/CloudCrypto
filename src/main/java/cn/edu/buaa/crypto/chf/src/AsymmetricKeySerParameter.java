package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;
import java.security.PrivateKey;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Asymmetric key serializable parameter.
 */
public class AsymmetricKeySerParameter implements CipherParameters, Serializable, PrivateKey {
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

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
