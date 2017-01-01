package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13MasterSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE master secret key parameter.
 */
public class CPABELLW14MasterSecretKeySerParameter extends CPABERW13MasterSecretKeySerParameter {
    public CPABELLW14MasterSecretKeySerParameter(PairingParameters pairingParameters, Element alpha) {
        super(pairingParameters, alpha);
    }
}
