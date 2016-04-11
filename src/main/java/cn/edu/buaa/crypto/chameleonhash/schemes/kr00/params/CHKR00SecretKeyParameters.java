package cn.edu.buaa.crypto.chameleonhash.schemes.kr00.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashPublicKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.params.ChameleonHashSecretKeyParameters;
import cn.edu.buaa.crypto.chameleonhash.schemes.kr00.CHKR00Engine;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00SecretKeyParameters extends ChameleonHashSecretKeyParameters {
    private final Element x;
    private CHKR00PublicKeyParameters publicKey;

    public CHKR00SecretKeyParameters(PairingParameters params, Element x) {
        super(params);
        this.x = x.getImmutable();
    }

    public void setPublicKeyParameters(ChameleonHashPublicKeyParameters publicKey) {
        if (publicKey instanceof CHKR00PublicKeyParameters) {
            this.publicKey = (CHKR00PublicKeyParameters)publicKey;
        } else {
            throw new IllegalArgumentException
                    ("Invalid ChameleonHashPublicKeyParameters for " + CHKR00Engine.SCHEME_NAME
                            + ", find "
                            + publicKey.getClass().getName() + ", require "
                            + CHKR00PublicKeyParameters.class.getName());
        }
    }

    public Element getX() { return this.x.duplicate(); }

    public ChameleonHashPublicKeyParameters getPublicKeyParameters() { return this.publicKey; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CHKR00SecretKeyParameters) {
            CHKR00SecretKeyParameters that = (CHKR00SecretKeyParameters)anObject;
            //Compare x
            if (!Utils.isEqualElement(this.x, that.getX())) {
                return false;
            }
            //Compare public key
            return this.publicKey.equals(that.getPublicKeyParameters());
        }
        return false;
    }

    public String getCHEngineName() {
        return CHKR00Engine.SCHEME_NAME;
    }
}
