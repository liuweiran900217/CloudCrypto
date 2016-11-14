package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters reovcation encryption ciphertext parameters.
 */
public class RELSW10aCipherSerParameter extends PairingCipherSerParameter {
    private final int length;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element[] C1s;
    private final byte[][] byteArraysC1s;

    private transient Element[] C2s;
    private final byte[][] byteArraysC2s;

    public RELSW10aCipherSerParameter(PairingParameters pairingParameters,
                                      int length, Element C0, Element[] C1s, Element[] C2s) {
        super(pairingParameters);
        this.length = length;

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.byteArraysC1s = PairingUtils.GetElementArrayBytes(this.C1s);

        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.byteArraysC2s = PairingUtils.GetElementArrayBytes(this.C2s);
    }

    public int getLength() { return this.length; }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1sAt(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC1s() { return this.C1s; }

    public Element getC2sAt(int index) { return this.C2s[index].duplicate(); }

    public Element[] getC2s() { return this.C2s; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aCipherSerParameter) {
            RELSW10aCipherSerParameter that = (RELSW10aCipherSerParameter) anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compre C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1s
            if (!PairingUtils.isEqualElementArray(this.C1s, that.getC1s())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!PairingUtils.isEqualElementArray(this.C2s, that.getC2s())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2s, that.byteArraysC2s)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0);
        this.C1s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC1s, PairingUtils.PairingGroupType.G1);
        this.C2s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC2s, PairingUtils.PairingGroupType.G1);
    }
}
