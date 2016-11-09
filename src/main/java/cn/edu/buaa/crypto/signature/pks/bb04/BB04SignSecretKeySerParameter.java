package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen signature secret key parameters.
 */
class BB04SignSecretKeySerParameter extends PairingKeySerParameter {
    private final Element x;
    private final Element y;
    private final BB04SignPublicKeySerParameter publicKeyParameters;

    BB04SignSecretKeySerParameter(PairingParameters parameters, BB04SignPublicKeySerParameter publicKeyParameters,
                                         Element x, Element y) {
        super(true, parameters);
        this.publicKeyParameters = publicKeyParameters;
        this.x = x.getImmutable();
        this.y = y.getImmutable();
    }

    public Element getX() {
        return this.x.duplicate();
    }

    public Element getY() {
        return this.y.duplicate();
    }

    public BB04SignPublicKeySerParameter getPublicKeyParameters() {
        return this.publicKeyParameters;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BB04SignSecretKeySerParameter) {
            BB04SignSecretKeySerParameter that = (BB04SignSecretKeySerParameter)anObject;
            //Compare x
            if (!PairingUtils.isEqualElement(this.x, that.getX())) {
                return false;
            }
            //Compare y
            if (!PairingUtils.isEqualElement(this.y, that.getY())) {
                return false;
            }
            //Compare public key parameters
            if (!this.publicKeyParameters.equals(that.getPublicKeyParameters())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
