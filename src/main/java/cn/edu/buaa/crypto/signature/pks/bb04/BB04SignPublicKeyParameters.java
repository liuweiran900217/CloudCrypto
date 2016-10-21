package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen signature public key.
 */
class BB04SignPublicKeyParameters extends PairingKeyParameters {
    private final Element g1;
    private final Element g2;
    private final Element u;
    private final Element v;

    public BB04SignPublicKeyParameters(PairingParameters parameters, Element g1, Element g2, Element u, Element v) {
        super(false, parameters);
        this.g1 = g1.getImmutable();
        this.g2 = g2.getImmutable();
        this.u = u.getImmutable();
        this.v = v.getImmutable();
    }

    public Element getG1() {
        return this.g1.duplicate();
    }

    public Element getG2() {
        return this.g2.duplicate();
    }

    public Element getU() {
        return this.u.duplicate();
    }

    public Element getV() {
        return this.v.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BB04SignPublicKeyParameters) {
            BB04SignPublicKeyParameters that = (BB04SignPublicKeyParameters)anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.getG2())) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
