package cn.edu.buaa.crypto.encryption.ibe.gen06b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aMasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CCA2-secure IBE master secret key parameter.
 */
public class IBEGen06bMasterSecretKeySerParameter extends IBEGen06aMasterSecretKeySerParameter {

    public IBEGen06bMasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(pairingParameters, alpha);
    }
}
