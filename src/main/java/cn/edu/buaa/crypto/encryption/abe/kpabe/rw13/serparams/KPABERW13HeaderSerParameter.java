package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams;

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
 * Created by Weiran Liu on 2016/11/30.
 *
 * Rouselakis-Waters KP-ABE header parameter.
 */
public class KPABERW13HeaderSerParameter extends PairingCipherSerParameter {
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Map<String, Element> C1s;
    private final Map<String, byte[]> byteArraysC1s;

    private transient Map<String, Element> C2s;
    private final Map<String, byte[]> byteArraysC2s;

    public KPABERW13HeaderSerParameter(PairingParameters pairingParameters, Element C0,
                                       Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters);

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new HashMap<String, byte[]>();

        this.C2s = new HashMap<String, Element>();
        this.byteArraysC2s = new HashMap<String, byte[]>();

        for (String attribute : C1s.keySet()) {
            this.C1s.put(attribute, C1s.get(attribute).duplicate().getImmutable());
            this.byteArraysC1s.put(attribute, C1s.get(attribute).duplicate().getImmutable().toBytes());

            this.C2s.put(attribute, C2s.get(attribute).duplicate().getImmutable());
            this.byteArraysC2s.put(attribute, C2s.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1sAt(String attribute) { return this.C1s.get(attribute).duplicate(); }

    public Element getC2sAt(String attribute) { return this.C2s.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABERW13HeaderSerParameter) {
            KPABERW13HeaderSerParameter that = (KPABERW13HeaderSerParameter)anObject;
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.C0)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!this.C2s.equals(that.C2s)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysC2s, that.byteArraysC2s)) {
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
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String attribute : this.byteArraysC1s.keySet()) {
            this.C1s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysC1s.get(attribute)).getImmutable());
            this.C2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysC2s.get(attribute)).getImmutable());
        }
    }
}
