package cn.edu.buaa.crypto.encryption.abe.cpabe.bsw07.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
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
 * Bethencourt-Sahai-Waters large-universe CP-ABE secret key parameter.
 */
public class CPABEBSW07SecretKeySerParameter extends PairingKeySerParameter {
    private transient Element D;
    private final byte[] byteArraysD;

    private transient Map<String, Element> D1s;
    private final Map<String, byte[]> byteArraysD1s;

    private transient Map<String, Element> D2s;
    private final Map<String, byte[]> byteArraysD2s;

    public CPABEBSW07SecretKeySerParameter(PairingParameters pairingParameters,
                                           Element D, Map<String, Element> D1s, Map<String, Element> D2s) {
        super(true, pairingParameters);

        this.D = D.getImmutable();
        this.byteArraysD = this.D.toBytes();

        this.D1s = new HashMap<String, Element>();
        this.byteArraysD1s = new HashMap<String, byte[]>();
        this.D2s = new HashMap<String, Element>();
        this.byteArraysD2s = new HashMap<String, byte[]>();

        for (String attribute : D1s.keySet()) {
            this.D1s.put(attribute, D1s.get(attribute).duplicate().getImmutable());
            this.byteArraysD1s.put(attribute, D1s.get(attribute).duplicate().getImmutable().toBytes());
            this.D2s.put(attribute, D2s.get(attribute).duplicate().getImmutable());
            this.byteArraysD2s.put(attribute, D2s.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.D1s.keySet().toArray(new String[1]); }

    public Element getD() { return this.D.duplicate(); }

    public Element getD1sAt(String attribute) { return this.D1s.get(attribute).duplicate(); }

    public Element getD2sAt(String attribute) { return this.D2s.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEBSW07SecretKeySerParameter) {
            CPABEBSW07SecretKeySerParameter that = (CPABEBSW07SecretKeySerParameter)anObject;
            //Compare D
            if (!PairingUtils.isEqualElement(this.D, that.D)) {
                return false;
            }
            if (!Arrays.equals(this.byteArraysD, that.byteArraysD)) {
                return false;
            }
            //compare D1s
            if (!this.D1s.equals(that.D1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysD1s, that.byteArraysD1s)) {
                return false;
            }
            //compare D2s
            if (!this.D2s.equals(that.D2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysD2s, that.byteArraysD2s)) {
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
        this.D = pairing.getG1().newElementFromBytes(this.byteArraysD);
        this.D1s = new HashMap<String, Element>();
        this.D2s = new HashMap<String, Element>();
        for (String attribute : this.byteArraysD1s.keySet()) {
            this.D1s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysD1s.get(attribute)).getImmutable());
            this.D2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysD2s.get(attribute)).getImmutable());
        }
    }
}