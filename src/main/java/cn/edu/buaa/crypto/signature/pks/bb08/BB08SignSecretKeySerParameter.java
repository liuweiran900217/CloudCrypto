package cn.edu.buaa.crypto.signature.pks.bb08;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/10.
 *
 * Boneh-Boyen 2008 signature secret key parameter.
 */
public class BB08SignSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element x;
    private final byte[] byteArrayX;

    private transient Element y;
    private final byte[] byteArrayY;

    BB08SignSecretKeySerParameter(PairingParameters parameters, Element g1, Element x, Element y) {
        super(true, parameters);
        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.x = x.getImmutable();
        this.byteArrayX = this.x.toBytes();

        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
    }

    public Element getG1() {
        return this.g1.duplicate();
    }

    public Element getX() {
        return this.x.duplicate();
    }

    public Element getY() {
        return this.y.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BB08SignSecretKeySerParameter) {
            BB08SignSecretKeySerParameter that = (BB08SignSecretKeySerParameter)anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
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
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());

        this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1);
        this.x = pairing.getZr().newElementFromBytes(this.byteArrayX);
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY);
    }
}
