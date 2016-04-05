package cn.edu.buaa.crypto.chameleonhash.kr00.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class CHKR00SecretKeyParameters extends PairingKeyParameters {
    private final Element x;

    private CHKR00PublicKeyParameters publicKey;

    public CHKR00SecretKeyParameters(PairingParameters params, Element x) {
        super(true, params);
        this.x = x.getImmutable();
    }

    public void setPublicKey(CHKR00PublicKeyParameters publicKey) {
        this.publicKey = publicKey;
    }

    public Element getX() { return this.x.duplicate(); }

    public CHKR00PublicKeyParameters getPublicKey() { return this.publicKey; }

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
            //Compare params
            return this.publicKey.equals(that.getPublicKey());
        }
        return false;
    }
}
