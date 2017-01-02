package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE public key parameter.
 */
public class KPABEHW14PublicKeySerParameter extends KPABERW13PublicKeySerParameter {
    public KPABEHW14PublicKeySerParameter(PairingParameters pairingParameters, Element g, Element u, Element h, Element w, Element eggAlpha) {
        super(pairingParameters, g, u, h, w, eggAlpha);
    }
}
