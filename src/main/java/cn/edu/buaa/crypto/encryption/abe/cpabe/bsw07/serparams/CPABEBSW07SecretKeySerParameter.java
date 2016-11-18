package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/18.
 *
 * Bethencourt-Sahai-Wtaers large-universe CP-ABE secret key parameter.
 */
public class CPABEBSW07SecretKeySerParameter extends PairingKeySerParameter {
    private final String[] attributes;
    private transient Element[] elementAttributes;
    private final byte[][] byteArraysElementAttributes;

    private transient Element D;
    private final byte[] byteArraysD;

    private transient Element[] D1s;
    private final byte[][] byteArraysD1s;

    private transient Element[] D2s;
    private final byte[][] byteArraysD2s;

    public CPABEBSW07SecretKeySerParameter(PairingParameters pairingParameters, String[] attributes, Element[] elementAttributes,
                                           Element D, Element[] D1s, Element[] D2s) {
        super(true, pairingParameters);

        this.attributes = attributes;
        this.elementAttributes = ElementUtils.cloneImmutable(elementAttributes);
        this.byteArraysElementAttributes = PairingUtils.GetElementArrayBytes(this.elementAttributes);

        this.D = D.getImmutable();
        this.byteArraysD = this.D.toBytes();

        this.D1s = ElementUtils.cloneImmutable(D1s);
        this.byteArraysD1s = PairingUtils.GetElementArrayBytes(this.D1s);

        this.D2s = ElementUtils.cloneImmutable(D2s);
        this.byteArraysD2s = PairingUtils.GetElementArrayBytes(this.D2s);
    }

    public String[] getAttributes() { return this.attributes; }

    public Element getD() { return this.D.duplicate(); }

    public Element getD1sAt(int index) { return this.D1s[index].duplicate(); }

    public Element getD2sAt(int index) { return this.D2s[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEBSW07SecretKeySerParameter) {
            CPABEBSW07SecretKeySerParameter that = (CPABEBSW07SecretKeySerParameter)anObject;
            //Compare attributes
            if (!Arrays.equals(this.attributes, that.attributes)) {
                return false;
            }
            if (!PairingUtils.isEqualElementArray(this.elementAttributes, that.elementAttributes)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysElementAttributes, that.byteArraysElementAttributes)) {
                return false;
            }
            //Compare D
            if (!PairingUtils.isEqualElement(this.D, that.D)) {
                return false;
            }
            if (!Arrays.equals(this.byteArraysD, that.byteArraysD)) {
                return false;
            }
            //compare D1s
            if (!PairingUtils.isEqualElementArray(this.D1s, that.D1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysD1s, that.byteArraysD1s)) {
                return false;
            }
            //compare D2s
            if (!PairingUtils.isEqualElementArray(this.D2s, that.D2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysD2s, that.byteArraysD2s)) {
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
        this.elementAttributes = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementAttributes, PairingUtils.PairingGroupType.G1);
        this.D = pairing.getG1().newElementFromBytes(this.byteArraysD);
        this.D1s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysD1s, PairingUtils.PairingGroupType.G1);
        this.D2s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysD2s, PairingUtils.PairingGroupType.G1);
    }
}