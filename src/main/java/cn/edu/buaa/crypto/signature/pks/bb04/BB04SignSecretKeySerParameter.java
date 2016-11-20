package cn.edu.buaa.crypto.signature.pks.bb04;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/10/17.
 *
 * Boneh-Boyen signature secret key parameters.
 */
class BB04SignSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element x;
    private final byte[] byteArrayX;

    private transient Element y;
    private final byte[] byteArrayY;

    private final BB04SignPublicKeySerParameter publicKeyParameters;

    BB04SignSecretKeySerParameter(PairingParameters parameters, BB04SignPublicKeySerParameter publicKeyParameters,
                                  Element x, Element y) {
        super(true, parameters);
        this.publicKeyParameters = publicKeyParameters;
        this.x = x.getImmutable();
        this.byteArrayX = this.x.toBytes();

        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
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
            if (!Arrays.equals(this.byteArrayX, that.byteArrayX)) {
                return false;
            }
            //Compare y
            if (!PairingUtils.isEqualElement(this.y, that.getY())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayY, that.byteArrayY)) {
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

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());

        this.x = pairing.getZr().newElementFromBytes(this.byteArrayX).getImmutable();
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY).getImmutable();
    }
}
