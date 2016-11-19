package cn.edu.buaa.crypto.signature.pks.bls01;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Boneh-Lynn-Shacham signature public key parameters.
 */
class BLS01SignPublicKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element v;
    private final byte[] byteArrayV;

    BLS01SignPublicKeySerParameter(PairingParameters parameters, Element g, Element v) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.v = v.getImmutable();
        this.byteArrayV = this.v.toBytes();
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
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());

        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.v = pairing.getG1().newElementFromBytes(this.byteArrayV).getImmutable();
    }
}