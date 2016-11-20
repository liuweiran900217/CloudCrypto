package cn.edu.buaa.crypto.encryption.hibbe.llw16a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 *
 * Liu-Liu-Wu prime-order HIBBE public key parameter.
 */
public class HIBBELLW16aPublicKeySerParameter extends PairingKeySerParameter {

    private final int maxUser;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element g2;
    private final byte[] byteArrayG2;

    private transient Element g3;
    private final byte[] byteArrayG3;

    private transient Element[] us;
    private final byte[][] byteArraysUs;

    public HIBBELLW16aPublicKeySerParameter(PairingParameters parameters, Element g, Element g1, Element g2, Element g3, Element[] us) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();

        this.g3 = g3.getImmutable();
        this.byteArrayG3 = this.g3.toBytes();

        this.us = ElementUtils.cloneImmutable(us);
        this.byteArraysUs = PairingUtils.GetElementArrayBytes(this.us);

        this.maxUser = us.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() { return this.g1.duplicate(); }

    public Element getG2() { return this.g2.duplicate(); }

    public Element getG3() { return this.g3.duplicate(); }

    public Element[] getUs() { return this.us; }

    public Element getUsAt(int index) {
        return this.us[index].duplicate();
    }

    public int getMaxUser() { return this.maxUser; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16aPublicKeySerParameter) {
            HIBBELLW16aPublicKeySerParameter that = (HIBBELLW16aPublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
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
            //Compare g3
            if (!PairingUtils.isEqualElement(this.g3, that.getG3())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG3, that.byteArrayG3)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElementArray(this.us, that.getUs())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysUs, that.byteArraysUs)) {
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
        this.g3 = pairing.getG1().newElementFromBytes(this.byteArrayG3).getImmutable();
        this.us = PairingUtils.GetElementArrayFromBytes(pairing, byteArraysUs, PairingUtils.PairingGroupType.G1);
    }
}

