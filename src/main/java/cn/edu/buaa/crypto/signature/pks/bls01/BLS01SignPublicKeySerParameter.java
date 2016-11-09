package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature public key parameters.
 */
class BLS01SignPublicKeySerParameter extends PairingKeySerParameter {
    private final Element g;
    private final Element v;

    BLS01SignPublicKeySerParameter(PairingParameters parameters, Element g, Element v) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.v = v.getImmutable();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getV() {
        return this.v.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BLS01SignPublicKeySerParameter) {
            BLS01SignPublicKeySerParameter that = (BLS01SignPublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
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