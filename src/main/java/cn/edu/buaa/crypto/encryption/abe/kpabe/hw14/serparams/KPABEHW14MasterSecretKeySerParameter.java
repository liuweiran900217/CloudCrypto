package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE master secret key parameter.
 */
public class KPABEHW14MasterSecretKeySerParameter extends KPABERW13MasterSecretKeySerParameter {
    public KPABEHW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(pairingParameters, alpha);
    }
}
