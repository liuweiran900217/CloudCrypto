package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE intermediate cipheretext parameter.
 */
public class KPABEHW14IntermediateSerParameter extends PairingCipherSerParameter {
    private final int n;

    private transient Element sessionKey;
    private final byte[] byteArraySessionKey;

    private transient Element s;
    private final byte[] byteArrayS;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element[] rs;
    private final byte[][] byteArraysRs;

    private transient Element[] xs;
    private final byte[][] byteArraysXs;

    private transient Element[] C1s;
    private final byte[][] byteArraysC1s;

    private transient Element[] C2s;
    private final byte[][] byteArraysC2s;

    public KPABEHW14IntermediateSerParameter(
            PairingParameters parameters, int n, Element sessionKey, Element s, Element C0,
            Element[] rs, Element[] xs, Element[] C1s, Element[] C2s) {
        super(parameters);
        this.n = n;

        this.sessionKey = sessionKey.getImmutable();
        this.byteArraySessionKey = this.sessionKey.toBytes();

        this.s = s.getImmutable();
        this.byteArrayS = this.s.toBytes();

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.rs = ElementUtils.cloneImmutable(rs);
        this.byteArraysRs = PairingUtils.GetElementArrayBytes(this.rs);

        this.xs = ElementUtils.cloneImmutable(xs);
        this.byteArraysXs = PairingUtils.GetElementArrayBytes(this.xs);

        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.byteArraysC1s = PairingUtils.GetElementArrayBytes(this.C1s);

        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.byteArraysC2s = PairingUtils.GetElementArrayBytes(this.C2s);
    }

    public int getN() { return this.n; }

    public Element getSessionKey() { return this.sessionKey.duplicate(); }

    public Element getS() { return this.s.duplicate(); }

    public Element getC0() { return this.C0.duplicate(); }

    public Element[] getRs() { return this.rs; }

    public Element getRsAt(int index) { return this.rs[index].duplicate(); }

    public Element[] getXs() { return this.xs; }

    public Element getXsAt(int index) { return this.xs[index].duplicate(); }

    public Element[] getC1s() { return this.C1s; }

    public Element getC1sAt(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC2s() { return this.C2s; }

    public Element getC2sAt(int index) { return this.C2s[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEHW14IntermediateSerParameter) {
            KPABEHW14IntermediateSerParameter that = (KPABEHW14IntermediateSerParameter)anObject;
            //compare n
            if (this.n != that.n) {
                return false;
            }
            //compare sessionKey
            if (!PairingUtils.isEqualElement(this.sessionKey, that.sessionKey)) {
                return false;
            }
            if (!Arrays.equals(this.byteArraySessionKey, that.byteArraySessionKey)) {
                return false;
            }
            //compare s
            if (!PairingUtils.isEqualElement(this.s, that.s)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayS, that.byteArrayS)) {
                return false;
            }
            //compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.C0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //compare rs
            if (!Arrays.equals(this.rs, that.rs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysRs, that.byteArraysRs)) {
                return false;
            }
            //compare xs
            if (!Arrays.equals(this.xs, that.xs)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysXs, that.byteArraysXs)) {
                return false;
            }
            //compare C1s
            if (!Arrays.equals(this.C1s, that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //compare C2s
            if (!Arrays.equals(this.C2s, that.C2s)) {
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
        this.sessionKey = pairing.getGT().newElementFromBytes(this.byteArraySessionKey).getImmutable();
        this.s = pairing.getZr().newElementFromBytes(this.byteArrayS).getImmutable();
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.rs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysRs, PairingUtils.PairingGroupType.Zr);
        this.xs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysXs, PairingUtils.PairingGroupType.Zr);
        this.C1s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC1s, PairingUtils.PairingGroupType.G1);
        this.C2s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC2s, PairingUtils.PairingGroupType.G1);
    }
}
