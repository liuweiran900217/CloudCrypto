package cn.edu.buaa.crypto.encryption.abe.kpabe.llw16.serparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams.KPABEHW14PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/3.
 *
 * Liu-Liu-Wu-16 CCA2-secure OO-KP-ABE public key parameter.
 */
public class KPABELLW16PublicKeySerParameter extends KPABEHW14PublicKeySerParameter {
    public KPABELLW16PublicKeySerParameter(PairingParameters pairingParameters, Element g, Element u, Element h, Element w, Element eggAlpha) {
        super(pairingParameters, g, u, h, w, eggAlpha);
    }
}
