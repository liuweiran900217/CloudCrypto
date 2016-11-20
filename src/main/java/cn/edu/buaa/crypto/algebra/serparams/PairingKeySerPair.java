package cn.edu.buaa.crypto.algebra.serparams;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * a holding class for pairing-based serializable public/private parameter pairs.
 */
public class PairingKeySerPair {
    private PairingKeySerParameter publicParam;
    private PairingKeySerParameter privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
    */
    public PairingKeySerPair(PairingKeySerParameter publicParam, PairingKeySerParameter privateParam)
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
    public PairingKeySerPair(CipherParameters publicParam, CipherParameters privateParam)
        {
            this.publicParam = (PairingKeySerParameter)publicParam;
            this.privateParam = (PairingKeySerParameter)privateParam;
        }

        /**
         * return the public key parameters.
         *
         * @return the public key parameters.
         */
    public PairingKeySerParameter getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public PairingKeySerParameter getPrivate()
    {
        return privateParam;
    }
}
