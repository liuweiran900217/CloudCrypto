package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE intermediate ciphertext parameter.
 */
public class CPABEHW14IntermediateSerParameter extends PairingCipherSerParameter {
    private final int n;

    private transient Element sessionKey;
    private final byte[] byteArraySessionKey;

    private transient Element s;
    private final byte[] byteArrayS;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element[] lambdas;
    private final byte[][] byteArraysLambdas;

    private transient Element[] ts;
    private final byte[][] byteArraysTs;

    private transient Element[] xs;
    private final byte[][] byteArraysXs;

    private transient Element[] C1s;
    private final byte[][] byteArraysC1s;

    private transient Element[] C2s;
    private final byte[][] byteArraysC2s;

    private transient Element[] C3s;
    private final byte[][] byteArraysC3s;

    public CPABEHW14IntermediateSerParameter(
            PairingParameters parameters, int n, Element sessionKey, Element s, Element C0,
            Element[] lambdas, Element[] ts, Element[] xs,
            Element[] C1s, Element[] C2s, Element[] C3s) {
        super(parameters);
        this.n = n;

        this.sessionKey = sessionKey.getImmutable();
        this.byteArraySessionKey = this.sessionKey.toBytes();

        this.s = s.getImmutable();
        this.byteArrayS = this.s.toBytes();

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.lambdas = ElementUtils.cloneImmutable(lambdas);
        this.byteArraysLambdas = PairingUtils.GetElementArrayBytes(this.lambdas);

        this.ts = ElementUtils.cloneImmutable(ts);
        this.byteArraysTs = PairingUtils.GetElementArrayBytes(this.ts);

        this.xs = ElementUtils.cloneImmutable(xs);
        this.byteArraysXs = PairingUtils.GetElementArrayBytes(this.xs);

        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.byteArraysC1s = PairingUtils.GetElementArrayBytes(this.C1s);

        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.byteArraysC2s = PairingUtils.GetElementArrayBytes(this.C2s);

        this.C3s = ElementUtils.cloneImmutable(C3s);
        this.byteArraysC3s = PairingUtils.GetElementArrayBytes(this.C3s);
    }

    public int getN() { return this.n; }

    public Element getSessionKey() { return this.sessionKey.duplicate(); }

    public Element getS() { return this.s.duplicate(); }

    public Element getC0() { return this.C0.duplicate(); }

    public Element[] getLambdas() { return ElementUtils.duplicate(lambdas); }

    public Element getLambdasAt(int index) { return this.lambdas[index].duplicate(); }

    public Element[] getTs() { return ElementUtils.duplicate(this.ts); }

    public Element getTsAt(int index) { return this.ts[index].duplicate(); }

    public Element[] getXs() { return ElementUtils.duplicate(this.xs); }

    public Element getXsAt(int index) { return this.xs[index].duplicate(); }

    public Element[] getC1s() { return ElementUtils.duplicate(this.C1s); }

    public Element getC1sAt(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC2s() { return ElementUtils.duplicate(this.C2s); }

    public Element getC2sAt(int index) { return this.C2s[index].duplicate(); }

    public Element[] getC3s() { return ElementUtils.duplicate(this.C3s); }

    public Element getC3sAt(int index) { return this.C3s[index].duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEHW14IntermediateSerParameter) {
            CPABEHW14IntermediateSerParameter that = (CPABEHW14IntermediateSerParameter)anObject;
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
            //compare lambdas
            if (!Arrays.equals(this.lambdas, that.lambdas)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysLambdas, that.byteArraysLambdas)) {
                return false;
            }
            //compare ts
            if (!Arrays.equals(this.ts, that.ts)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysTs, that.byteArraysTs)) {
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
            //compare C3s
            if (!Arrays.equals(this.C3s, that.C3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC3s, that.byteArraysC3s)) {
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
        this.lambdas = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysLambdas, PairingUtils.PairingGroupType.Zr);
        this.ts = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysTs, PairingUtils.PairingGroupType.Zr);
        this.xs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysXs, PairingUtils.PairingGroupType.Zr);
        this.C1s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC1s, PairingUtils.PairingGroupType.G1);
        this.C2s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC2s, PairingUtils.PairingGroupType.G1);
        this.C3s = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysC3s, PairingUtils.PairingGroupType.G1);
    }
}
