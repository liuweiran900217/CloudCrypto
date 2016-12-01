package cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams;

import cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams.HIBBELLW14MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE master secret key parameter.
 */
public class HIBBELLW17MasterSecretKeySerParameter extends HIBBELLW14MasterSecretKeySerParameter {

    public HIBBELLW17MasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha) {
        super(pairingParameters, gAlpha);
    }
}