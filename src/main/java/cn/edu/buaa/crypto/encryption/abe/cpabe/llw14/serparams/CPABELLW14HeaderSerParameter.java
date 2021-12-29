package cn.edu.buaa.crypto.encryption.abe.cpabe.llw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/12/28.
 *
 * Liu-Liu-Wu-14 CCA2-secure CP-ABE header parameter.
 */
public class CPABELLW14HeaderSerParameter extends PairingCipherSerParameter {
    protected final String[] rhos;
    protected transient Element C0;
    protected final byte[] byteArrayC0;

    protected transient Map<String, Element> C1s;
    private final byte[][] byteArraysC1s;

    protected transient Map<String, Element> C2s;
    private final byte[][] byteArraysC2s;

    protected transient Map<String, Element> C3s;
    private final byte[][] byteArraysC3s;

    private final byte[] chameleonHash;
    private final byte[] r;

    private transient Element C01;
    private final byte[] byteArrayC01;

    private transient Element C02;
    private final byte[] byteArrayC02;

    private transient Element C03;
    private final byte[] byteArrayC03;

    public CPABELLW14HeaderSerParameter(
            PairingParameters pairingParameters, byte[] chameleonHash, byte[] r, Element C01, Element C02, Element C03,
            Element C0, Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
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
        }

        this.chameleonHash = chameleonHash;
        this.r = r;

        this.C01 = C01.getImmutable();
        this.byteArrayC01 = this.C01.toBytes();

        this.C02 = C02.getImmutable();
        this.byteArrayC02 = this.C02.toBytes();

        this.C03 = C03.getImmutable();
        this.byteArrayC03 = this.C03.toBytes();
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Map<String, Element> getC1s() { return this.C1s; }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Map<String, Element> getC2s() { return this.C2s; }

    public Element getC2sAt(String rho) { return this.C2s.get(rho).duplicate(); }

    public Map<String, Element> getC3s() { return this.C3s; }

    public Element getC3sAt(String rho) { return this.C3s.get(rho).duplicate(); }

    public byte[] getChameleonHash() { return this.chameleonHash; }

    public byte[] getR() {
        return this.r;
    }

    public Element getC01() { return this.C01.duplicate(); }

    public Element getC02() { return this.C02.duplicate(); }

    public Element getC03() { return this.C03.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABELLW14HeaderSerParameter) {
            CPABELLW14HeaderSerParameter that = (CPABELLW14HeaderSerParameter) anObject;
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
            if (!PairingUtils.isEqualElement(this.C01, that.C01)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC01, that.byteArrayC01)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C02, that.C02)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC02, that.byteArrayC02)) {
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C03, that.C03)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC03, that.byteArrayC03)) {
                return false;
            }
            //Compare chameleon hash key
            return Arrays.equals(this.r, that.r)
                    && Arrays.equals(this.chameleonHash, that.chameleonHash)
                    && super.equals(anObject);
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
        for (int i = 0; i < this.rhos.length; i++) {
            this.C1s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC1s[i]).getImmutable());
            this.C2s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC2s[i]).getImmutable());
            this.C3s.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC3s[i]).getImmutable());
        }
        this.C01 = pairing.getG1().newElementFromBytes(this.byteArrayC01).getImmutable();
        this.C02 = pairing.getG1().newElementFromBytes(this.byteArrayC02).getImmutable();
        this.C03 = pairing.getG1().newElementFromBytes(this.byteArrayC03).getImmutable();
    }
}
