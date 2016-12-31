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

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE secret key parameter.
 */
public class CPABERW13SecretKeySerParameter extends PairingKeySerParameter {
    private transient Element K0;
    private final byte[] byteArrayK0;

    private transient Element K1;
    private final byte[] byteArrayK1;

    private transient Map<String, Element> K2s;
    private final Map<String, byte[]> byteArraysK2s;

    private transient Map<String, Element> K3s;
    private final Map<String, byte[]> byteArraysK3s;

    public CPABERW13SecretKeySerParameter(PairingParameters pairingParameters, Element K0, Element K1,
                                          Map<String, Element> K2s, Map<String, Element> K3s) {
        super(true, pairingParameters);

        this.K0 = K0.getImmutable();
        this.byteArrayK0 = this.K0.toBytes();

        this.K1 = K1.getImmutable();
        this.byteArrayK1 = this.K1.toBytes();

        this.K2s = new HashMap<String, Element>();
        this.byteArraysK2s = new HashMap<String, byte[]>();
        this.K3s = new HashMap<String, Element>();
        this.byteArraysK3s = new HashMap<String, byte[]>();

        for (String attribute : K2s.keySet()) {
            this.K2s.put(attribute, K2s.get(attribute).duplicate().getImmutable());
            this.byteArraysK2s.put(attribute, K2s.get(attribute).duplicate().getImmutable().toBytes());
            this.K3s.put(attribute, K3s.get(attribute).duplicate().getImmutable());
            this.byteArraysK3s.put(attribute, K3s.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public String[] getAttributes() { return this.K2s.keySet().toArray(new String[1]); }

    public Element getK0() { return this.K0.duplicate(); }

    public Element getK1() { return this.K1.duplicate(); }

    public Map<String, Element> getK2s() { return this.K2s; }

    public Element getK2sAt(String attribute) { return this.K2s.get(attribute).duplicate(); }

    public Map<String, Element> getK3s() { return this.K3s; }

    public Element getK3sAt(String attribute) { return this.K3s.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13SecretKeySerParameter) {
            CPABERW13SecretKeySerParameter that = (CPABERW13SecretKeySerParameter)anObject;
            //Compare K0
            if (!PairingUtils.isEqualElement(this.K0, that.K0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK0, that.byteArrayK0)) {
                return false;
            }
            //Compare k1
            if (!PairingUtils.isEqualElement(this.K1, that.K1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK1, that.byteArrayK1)) {
                return false;
            }
            //compare K2s
            if (!this.K2s.equals(that.K2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysK2s, that.byteArraysK2s)) {
                return false;
            }
            //compare K3s
            if (!this.K3s.equals(that.K3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysK3s, that.byteArraysK3s)) {
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
        this.K0 = pairing.getG1().newElementFromBytes(this.byteArrayK0);
        this.K1 = pairing.getG1().newElementFromBytes(this.byteArrayK1);
        this.K2s = new HashMap<String, Element>();
        this.K3s = new HashMap<String, Element>();
        for (String attribute : this.byteArraysK2s.keySet()) {
            this.K2s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysK2s.get(attribute)).getImmutable());
            this.K3s.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysK3s.get(attribute)).getImmutable());
        }
    }
}