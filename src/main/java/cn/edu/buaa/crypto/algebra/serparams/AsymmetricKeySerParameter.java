package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Serializable asymmetric key parameter.
 * This is the same as AsymmetricKeyParameters, except that this is serializable.
 * All the asymmetric key parameters should extend this class for supporting serialization.
 */
public class AsymmetricKeySerParameter implements CipherParameters, Serializable {
    private boolean privateKey;

    public AsymmetricKeySerParameter(
            boolean privateKey)
    {
        this.privateKey = privateKey;
    }

    public boolean isPrivate()
    {
        return privateKey;
    }
}
