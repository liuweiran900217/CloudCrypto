package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams;

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
 * Created by Weiran Liu on 2016/11/18.
 *
 * Bethencourt-Sahai-Waters large-universe CP-ABE header parameter.
 */
public class CPABEBSW07HeaderSerParameter extends PairingCipherSerParameter {
    private transient Element C;
    private final byte[] byteArrayC;

    private transient Map<String, Element> C1s;
    private final Map<String, byte[]> byteArraysC1s;

    private transient Map<String, Element> C2s;
    private final Map<String, byte[]> byteArraysC2s;

    public CPABEBSW07HeaderSerParameter(
            PairingParameters pairingParameters, Element C,
            Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters);

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();

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

    public Element getC() { return this.C.duplicate(); }

    public Element getC1sAt(String rho) { return this.C1s.get(rho).duplicate(); }

    public Element getC2sAt(String rho) { return this.C2s.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEBSW07HeaderSerParameter) {
            CPABEBSW07HeaderSerParameter that = (CPABEBSW07HeaderSerParameter)anObject;
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.C)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
                return false;
            }
            //Compare C1s
            if (!this.C1s.equals(that.C1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysC1s, that.byteArraysC1s)) {
                return false;
            }
            //Compare C2s
            if (!this.C2s.equals(that.C2s)) {
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
        this.C = pairing.getG1().newElementFromBytes(this.byteArrayC).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String attribute : byteArraysC1s.keySet()) {
            this.C1s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysC1s.get(attribute)).getImmutable());
            this.C2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysC2s.get(attribute)).getImmutable());
        }
    }
}
