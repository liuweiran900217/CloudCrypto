package cn.edu.buaa.crypto.encryption.re.llw16b.serparams;

import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aSecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE secret key parameter.
 */
public class RELLW16bSecretKeySerParameter extends RELLW16aSecretKeySerParameter {
    public RELLW16bSecretKeySerParameter(
            PairingParameters pairingParameters, String id, Element elementId, Element d0, Element d1, Element d2) {
        super(pairingParameters, id, elementId, d0, d1, d2);
    }
}
