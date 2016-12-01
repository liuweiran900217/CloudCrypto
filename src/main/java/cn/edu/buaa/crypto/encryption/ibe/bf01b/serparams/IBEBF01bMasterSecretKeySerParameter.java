package cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE master secret key parameter.
 */
public class IBEBF01bMasterSecretKeySerParameter extends IBEBF01aMasterSecretKeySerParameter {

    public IBEBF01bMasterSecretKeySerParameter(IBEBF01aMasterSecretKeySerParameter masterSecretKeyParameter) {
        super(masterSecretKeyParameter.getParameters(), masterSecretKeyParameter.getS());
    }
}
