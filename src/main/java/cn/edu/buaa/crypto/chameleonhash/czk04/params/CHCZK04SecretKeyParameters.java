package cn.edu.buaa.crypto.chameleonhash.czk04.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

import java.math.BigInteger;

/**
 * Created by Weiran Liu on 2016/4/4.
 */
public class CHCZK04SecretKeyParameters extends PairingKeyParameters {
    private final Element x;

    private CHCZK04PublicKeyParameters publicKey;

    public CHCZK04SecretKeyParameters(PairingParameters params, Element x) {
        super(true, params);
        this.x = x.getImmutable();
    }

    public void setPublicKey(CHCZK04PublicKeyParameters publicKey) {
        this.publicKey = publicKey;
    }

    public Element getX() { return this.x.duplicate(); }

    public CHCZK04PublicKeyParameters getPublicKey() { return this.publicKey; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
             return true;
        }
        if (anObject instanceof CHCZK04SecretKeyParameters) {
            CHCZK04SecretKeyParameters that = (CHCZK04SecretKeyParameters)anObject;
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
