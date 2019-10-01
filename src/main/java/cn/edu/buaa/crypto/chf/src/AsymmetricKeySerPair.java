package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * a holding class for serializable public/private parameter pairs.
 */
public class AsymmetricKeySerPair {
    private AsymmetricKeySerParameter publicParam;
    private AsymmetricKeySerParameter privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     */
    public AsymmetricKeySerPair(AsymmetricKeySerParameter publicParam, AsymmetricKeySerParameter privateParam)
    {
        this.publicParam = publicParam;
        this.privateParam = privateParam;
    }

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     * @deprecated use AsymmetricKeyParameter
     */
    public AsymmetricKeySerPair(CipherParameters publicParam, CipherParameters privateParam)
    {
        this.publicParam = (AsymmetricKeySerParameter)publicParam;
        this.privateParam = (AsymmetricKeySerParameter)privateParam;
    }

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public AsymmetricKeySerParameter getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public AsymmetricKeySerParameter getPrivate()
    {
        return privateParam;
    }
}
