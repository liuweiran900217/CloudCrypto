package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE secret key parameter.
 */
public class CPABELLW14SecretKeySerParameter extends CPABERW13SecretKeySerParameter {
    public CPABELLW14SecretKeySerParameter(PairingParameters pairingParameters, Element K0, Element K1, Map<String, Element> K2s, Map<String, Element> K3s) {
        super(pairingParameters, K0, K1, K2s, K3s);
    }
}
