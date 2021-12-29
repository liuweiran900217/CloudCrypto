package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class CPABERW13ReKeySerParameter extends PairingKeySerParameter {
    private transient Element d0;
    private final byte[] byteArrayD0;

    private transient Element d1;
    private final byte[] byteArrayD1;

    private transient Map<String, Element> d2s;
    private final Map<String, byte[]> byteArraysD2s;

    private transient Map<String, Element> d3s;
    private final Map<String, byte[]> byteArraysD3s;

    private transient Element d4;
    private final byte[] byteArrayD4;

    private transient Element d5;
    private final byte[] byteArrayD5;

    private transient Element d6;
    private final byte[] byteArrayD6;

    public CPABERW13ReKeySerParameter(PairingParameters pairingParameters, Element d0, Element d1,
                                          Map<String, Element> d2s, Map<String, Element> d3s,
                                      Element d4, Element d5, Element d6) {
        super(true, pairingParameters);

        this.d0 = d0.getImmutable();
        this.byteArrayD0 = this.d0.toBytes();

        this.d1 = d1.getImmutable();
        this.byteArrayD1 = this.d1.toBytes();

        this.d2s = new HashMap<String, Element>();
        this.byteArraysD2s = new HashMap<String, byte[]>();
        this.d3s = new HashMap<String, Element>();
        this.byteArraysD3s = new HashMap<String, byte[]>();

        for (String attribute : d2s.keySet()) {
            this.d2s.put(attribute, d2s.get(attribute).duplicate().getImmutable());
            this.byteArraysD2s.put(attribute, d2s.get(attribute).duplicate().getImmutable().toBytes());
            this.d3s.put(attribute, d3s.get(attribute).duplicate().getImmutable());
            this.byteArraysD3s.put(attribute, d3s.get(attribute).duplicate().getImmutable().toBytes());
        }

        this.d4 = d4.getImmutable();
        this.byteArrayD4 = this.d4.toBytes();

        this.d5 = d5.getImmutable();
        this.byteArrayD5 = this.d5.toBytes();

        this.d6 = d6.getImmutable();
        this.byteArrayD6 = this.d6.toBytes();
    }

    public String[] getAttributes() { return this.d2s.keySet().toArray(new String[1]); }

    public Element getD0() { return this.d0.duplicate(); }

    public Element getD1() { return this.d1.duplicate(); }

    public Map<String, Element> getD2s() { return this.d2s; }

    public Element getD2sAt(String attribute) { return this.d2s.get(attribute).duplicate(); }

    public Map<String, Element> getK3s() { return this.d3s; }

    public Element getD3sAt(String attribute) { return this.d3s.get(attribute).duplicate(); }

    public Element getD4() { return this.d4.duplicate(); }

    public Element getD5() { return this.d5.duplicate(); }

    public Element getD6() { return this.d6.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13ReKeySerParameter) {
            CPABERW13ReKeySerParameter that = (CPABERW13ReKeySerParameter)anObject;
            //Compare d0
            if (!PairingUtils.isEqualElement(this.d0, that.d0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD0, that.byteArrayD0)) {
                return false;
            }
            //Compare d1
            if (!PairingUtils.isEqualElement(this.d1, that.d1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD1, that.byteArrayD1)) {
                return false;
            }
            //compare d2s
            if (!this.d2s.equals(that.d2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysD2s, that.byteArraysD2s)) {
                return false;
            }
            //compare d3s
            if (!this.d3s.equals(that.d3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysD3s, that.byteArraysD3s)) {
                return false;
            }
            //Compare d4
            if (!PairingUtils.isEqualElement(this.d4, that.d4)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD4, that.byteArrayD4)) {
                return false;
            }
            //Compare d5
            if (!PairingUtils.isEqualElement(this.d5, that.d5)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD5, that.byteArrayD5)) {
                return false;
            }
            //Compare d6
            if (!PairingUtils.isEqualElement(this.d6, that.d6)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD6, that.byteArrayD6)) {
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
        this.d0 = pairing.getG1().newElementFromBytes(this.byteArrayD0);
        this.d1 = pairing.getG1().newElementFromBytes(this.byteArrayD1);
        this.d2s = new HashMap<String, Element>();
        this.d3s = new HashMap<String, Element>();
        for (String attribute : this.byteArraysD2s.keySet()) {
            this.d2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysD2s.get(attribute)).getImmutable());
            this.d3s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysD3s.get(attribute)).getImmutable());
        }
        this.d4 = pairing.getG1().newElementFromBytes(this.byteArrayD4);
        this.d5 = pairing.getG1().newElementFromBytes(this.byteArrayD5);
        this.d6 = pairing.getG1().newElementFromBytes(this.byteArrayD6);
    }
}
