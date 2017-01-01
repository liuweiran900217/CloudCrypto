package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE header parameter.
 */
public class CPABEHW14HeaderSerParameter extends PairingCipherSerParameter {
    private final String[] rhos;

    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Map<String, Element> C1s;
    private final byte[][] byteArraysC1s;

    private transient Map<String, Element> C2s;
    private final byte[][] byteArraysC2s;

    private transient Map<String, Element> C3s;
    private final byte[][] byteArraysC3s;

    private transient Map<String, Element> C4s;
    private final byte[][] byteArraysC4s;

    private transient Map<String, Element> C5s;
    private final byte[][] byteArraysC5s;

    public CPABEHW14HeaderSerParameter(PairingParameters pairingParameters, Element C0,
                                       Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s,
                                       Map<String, Element> C4s, Map<String, Element> C5s) {
        super(pairingParameters);

        this.rhos = C1s.keySet().toArray(new String[1]);
        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new byte[this.rhos.length][];
        this.C2s = new HashMap<String, Element>();
        this.byteArraysC2s = new byte[this.rhos.length][];
        this.C3s = new HashMap<String, Element>();
        this.byteArraysC3s = new byte[this.rhos.length][];
        this.C4s = new HashMap<String, Element>();
        this.byteArraysC4s = new byte[this.rhos.length][];
        this.C5s = new HashMap<String, Element>();
        this.byteArraysC5s = new byte[this.rhos.length][];

        for (int i = 0; i < this.rhos.length; i++) {
            Element C1 = C1s.get(this.rhos[i]).duplicate().getImmutable();
            this.C1s.put(this.rhos[i], C1);
            this.byteArraysC1s[i] = C1.toBytes();

            Element C2 = C2s.get(this.rhos[i]).duplicate().getImmutable();
            this.C2s.put(this.rhos[i], C2);
            this.byteArraysC2s[i] = C2.toBytes();

            Element C3 = C3s.get(this.rhos[i]).duplicate().getImmutable();
            this.C3s.put(this.rhos[i], C3);
            this.byteArraysC3s[i] = C3.toBytes();

            Element C4 = C4s.get(this.rhos[i]).duplicate().getImmutable();
            this.C4s.put(this.rhos[i], C4);
            this.byteArraysC4s[i] = C4.toBytes();

            Element C5 = C5s.get(this.rhos[i]).duplicate().getImmutable();
            this.C5s.put(this.rhos[i], C5);
            this.byteArraysC5s[i] = C5.toBytes();
        }
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Element getC2sAt(String rho) { return this.C2s.get(rho).duplicate(); }

    public Element getC3sAt(String rho) { return this.C3s.get(rho).duplicate(); }

    public Element getC4sAt(String rho) { return this.C4s.get(rho).duplicate(); }

    public Element getC5sAt(String rho) { return this.C5s.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEHW14HeaderSerParameter) {
            CPABEHW14HeaderSerParameter that = (CPABEHW14HeaderSerParameter)anObject;
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.C0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!this.C2s.equals(that.C2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2s, that.byteArraysC2s)) {
                return false;
            }
            //Compare C3s
            if (!this.C3s.equals(that.C3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC3s, that.byteArraysC3s)) {
                return false;
            }
            //Compare C4s
            if (!this.C4s.equals(that.C4s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC4s, that.byteArraysC4s)) {
                return false;
            }
            //Compare C5s
            if (!this.C5s.equals(that.C5s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC5s, that.byteArraysC5s)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        this.C3s = new HashMap<String, Element>();
        this.C4s = new HashMap<String, Element>();
        this.C5s = new HashMap<String, Element>();
        for (int i = 0; i < this.rhos.length; i++) {
            this.C1s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC1s[i]).getImmutable());
            this.C2s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC2s[i]).getImmutable());
            this.C3s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC3s[i]).getImmutable());
            this.C4s.put(this.rhos[i], pairing.getZr().newElementFromBytes(this.byteArraysC4s[i]).getImmutable());
            this.C5s.put(this.rhos[i], pairing.getZr().newElementFromBytes(this.byteArraysC5s[i]).getImmutable());
        }
    }
}
