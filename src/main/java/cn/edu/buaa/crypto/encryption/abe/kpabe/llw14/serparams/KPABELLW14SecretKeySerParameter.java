package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE secret key parameter.
 */
public class KPABELLW14SecretKeySerParameter extends KPABERW13SecretKeySerParameter {
    public KPABELLW14SecretKeySerParameter(
            PairingParameters pairingParameters, AccessControlParameter accessControlParameter,
            Map<String, Element> K0s, Map<String, Element> K1s, Map<String, Element> K2s) {
        super(pairingParameters, accessControlParameter, K0s, K1s, K2s);
    }
}
