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
 * Boneh-Boyen 2008 signature public key.
 */
public class BB08SignPublicKeySerParameter extends PairingKeySerParameter {
    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element g2;
    private final byte[] byteArrayG2;

    private transient Element u;
    private final byte[] byteArrayU;

    private transient Element v;
    private final byte[] byteArrayV;

    private transient Element z;
    private final byte[] byteArrayZ;

    BB08SignPublicKeySerParameter(PairingParameters parameters, Element g1, Element g2, Element u, Element v, Element z) {
        super(false, parameters);
        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();

        this.u = u.getImmutable();
        this.byteArrayU = this.u.toBytes();

        this.v = v.getImmutable();
        this.byteArrayV = this.v.toBytes();

        this.z = z.getImmutable();
        this.byteArrayZ = this.z.toBytes();
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

    public Element getZ() {
        return this.z.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BB08SignPublicKeySerParameter) {
            BB08SignPublicKeySerParameter that = (BB08SignPublicKeySerParameter)anObject;
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.getG2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2, that.byteArrayG2)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
                return false;
            }
            //Compare z
            if (!PairingUtils.isEqualElement(this.z, that.getZ())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayZ, that.byteArrayZ)) {
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
        this.g2 = pairing.getG2().newElementFromBytes(this.byteArrayG2);
        this.u = pairing.getG2().newElementFromBytes(this.byteArrayU);
        this.v = pairing.getG2().newElementFromBytes(this.byteArrayV);
        this.z = pairing.getGT().newElementFromBytes(this.byteArrayZ);
    }
}
