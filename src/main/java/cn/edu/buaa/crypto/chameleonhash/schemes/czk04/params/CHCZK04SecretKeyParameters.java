package cn.edu.buaa.crypto.chameleonhash.schemes.czk04.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.czk04.CHCZK04Engine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHCZK04SecretKeyParameters extends ChameleonHashSecretKeyParameters {
    private final Element x;

    private CHCZK04PublicKeyParameters publicKey;

    public CHCZK04SecretKeyParameters(PairingParameters params, Element x) {
        super(params);
        this.x = x.getImmutable();
    }

    public void setPublicKeyParameters(ChameleonHashPublicKeyParameters publicKey) {
        if (publicKey instanceof CHCZK04PublicKeyParameters) {
            this.publicKey = (CHCZK04PublicKeyParameters)publicKey;
        } else {
            throw new IllegalArgumentException
                    ("Invalid ChameleonHashPublicKeyParameters for " + CHCZK04Engine.SCHEME_NAME
                            + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CHCZK04PublicKeyParameters.class.getName());
        }
    }

    public Element getX() { return this.x.duplicate(); }

    public ChameleonHashPublicKeyParameters getPublicKeyParameters() { return this.publicKey; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
             return true;
        }
        if (anObject instanceof CHCZK04SecretKeyParameters) {
            CHCZK04SecretKeyParameters that = (CHCZK04SecretKeyParameters)anObject;
            //Compare x
            if (!PairingUtils.isEqualElement(this.x, that.getX())) {
                return false;
            }
            //Compare public key
            return this.publicKey.equals(that.getPublicKeyParameters());
        }
        return false;
    }

    public String getCHEngineName() {
        return CHCZK04Engine.SCHEME_NAME;
    }
}
