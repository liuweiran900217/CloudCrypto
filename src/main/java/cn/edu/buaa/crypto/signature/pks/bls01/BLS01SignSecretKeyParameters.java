package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature secret key parameters.
 */
class BLS01SignSecretKeyParameters extends PairingKeyParameters {
    private final Element x;

    public BLS01SignSecretKeyParameters(PairingParameters parameters, Element x) {
        super(true, parameters);
        this.x = x.getImmutable();
    }

    public Element getX() {
        return this.x.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BLS01SignSecretKeyParameters) {
            BLS01SignSecretKeyParameters that = (BLS01SignSecretKeyParameters)anObject;
            //Compare x
            if (!PairingUtils.isEqualElement(this.x, that.getX())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
