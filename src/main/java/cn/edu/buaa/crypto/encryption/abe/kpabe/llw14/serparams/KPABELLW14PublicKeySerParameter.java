package cn.edu.buaa.crypto.encryption.abe.kpabe.llw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Liu-Liu-Wu-14 CCA2-secure KP-ABE public key parameter.
 */
public class KPABELLW14PublicKeySerParameter extends KPABERW13PublicKeySerParameter {
    private AsymmetricKeySerParameter chameleonHashPublicKey;


    public KPABELLW14PublicKeySerParameter(
            PairingParameters pairingParameters, AsymmetricKeySerParameter chameleonHashPublicKey,
            Element g, Element u, Element h, Element w, Element eggAlpha) {
        super(pairingParameters, g, u, h, w, eggAlpha);
        this.chameleonHashPublicKey = chameleonHashPublicKey;
    }

    public AsymmetricKeySerParameter getChameleonHashPublicKey() {
        return this.chameleonHashPublicKey;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABELLW14PublicKeySerParameter) {
            KPABELLW14PublicKeySerParameter that = (KPABELLW14PublicKeySerParameter) anObject;
            //Compare chPublicKey
            return this.chameleonHashPublicKey.equals(that.chameleonHashPublicKey) && super.equals(anObject);
        }
        return false;
    }
}
