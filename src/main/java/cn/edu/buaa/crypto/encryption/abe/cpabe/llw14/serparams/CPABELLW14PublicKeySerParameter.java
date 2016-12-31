package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.AsymmetricKeySerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13PublicKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE public key parameter.
 */
public class CPABELLW14PublicKeySerParameter extends CPABERW13PublicKeySerParameter {
    private AsymmetricKeySerParameter chameleonHashPublicKey;

    public CPABELLW14PublicKeySerParameter(
            PairingParameters parameters, AsymmetricKeySerParameter chameleonHashPublicKey,
            Element g, Element u, Element h, Element w, Element v, Element eggAlpha) {
        super(parameters, g, u, h, w, v, eggAlpha);
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
        if (anObject instanceof CPABELLW14PublicKeySerParameter) {
            CPABELLW14PublicKeySerParameter that = (CPABELLW14PublicKeySerParameter) anObject;
            //Compare chPublicKey
            return this.chameleonHashPublicKey.equals(that.chameleonHashPublicKey) && super.equals(anObject);
        }
        return false;
    }
}
