package cn.edu.buaa.crypto.encryption.abe.cpabe.llw16.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams.CPABEHW14SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.util.Map;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Liu-Liu-Wu-16 CCA2-secure CP-ABE secret key parameter.
 */
public class CPABELLW16SecretKeySerParameter extends CPABEHW14SecretKeySerParameter {
    public CPABELLW16SecretKeySerParameter(
            PairingParameters pairingParameters, Element K0, Element K1,
            Map<String, Element> K2s, Map<String, Element> K3s) {
        super(pairingParameters, K0, K1, K2s, K3s);
    }
}
