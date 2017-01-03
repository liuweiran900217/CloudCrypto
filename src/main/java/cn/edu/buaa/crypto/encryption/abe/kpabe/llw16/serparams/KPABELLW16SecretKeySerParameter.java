package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE secret key parameter.
 */
public class KPABELLW16SecretKeySerParameter extends KPABEHW14SecretKeySerParameter {
    public KPABELLW16SecretKeySerParameter(
            PairingParameters pairingParameters, AccessControlParameter accessControlParameter,
            Map<String, Element> K0s, Map<String, Element> K1s, Map<String, Element> K2s) {
        super(pairingParameters, accessControlParameter, K0s, K1s, K2s);
    }
}
