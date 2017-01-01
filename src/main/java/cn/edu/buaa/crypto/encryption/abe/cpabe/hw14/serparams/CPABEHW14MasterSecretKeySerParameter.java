package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE master secret key parameter.
 */
public class CPABEHW14MasterSecretKeySerParameter extends CPABERW13MasterSecretKeySerParameter {
    public CPABEHW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(pairingParameters, alpha);
    }
}
