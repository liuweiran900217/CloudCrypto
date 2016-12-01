package cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE public key parameter.
 */
public class IBEBF01bPublicKeySerParameter extends IBEBF01aPublicKeySerParameter {
    public IBEBF01bPublicKeySerParameter(IBEBF01aPublicKeySerParameter publicKeyParameter) {
        super(publicKeyParameter.getParameters(), publicKeyParameter.getG(), publicKeyParameter.getGs());
    }
}
