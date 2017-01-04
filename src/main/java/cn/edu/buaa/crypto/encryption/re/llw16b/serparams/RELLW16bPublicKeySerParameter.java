package cn.edu.buaa.crypto.encryption.re.llw16b.serparams;

import cn.edu.buaa.crypto.encryption.re.llw16a.serparams.RELLW16aPublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-RE public key parameter.
 */
public class RELLW16bPublicKeySerParameter extends RELLW16aPublicKeySerParameter {
    public RELLW16bPublicKeySerParameter(
            PairingParameters parameters, Element g, Element g_b, Element g_b2, Element h_b, Element e_g_g_alpha) {
        super(parameters, g, g_b, g_b2, h_b, e_g_g_alpha);
    }
}
