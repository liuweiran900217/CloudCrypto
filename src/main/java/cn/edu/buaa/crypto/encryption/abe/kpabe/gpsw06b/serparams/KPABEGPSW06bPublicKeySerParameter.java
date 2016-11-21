package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles public key parameter.
 */
public class KPABEGPSW06bPublicKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element g2;
    private final byte[] byteArrayG2;

    public KPABEGPSW06bPublicKeySerParameter(PairingParameters pairingParameters, Element g, Element g1, Element g2) {
        super(true, pairingParameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() {
        return this.g1.duplicate();
    }

    public Element getG2() {
        return this.g2.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06bPublicKeySerParameter) {
            KPABEGPSW06bPublicKeySerParameter that = (KPABEGPSW06bPublicKeySerParameter) anObject;
            //compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.g1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
            //compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.g2)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2, that.byteArrayG2)) {
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
        this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1).getImmutable();
        this.g2 = pairing.getG1().newElementFromBytes(this.byteArrayG2).getImmutable();
    }
}