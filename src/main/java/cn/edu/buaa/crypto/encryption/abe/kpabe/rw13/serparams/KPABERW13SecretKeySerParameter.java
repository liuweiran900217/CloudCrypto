package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams;

import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/30.
 *
 * Rouselakis-Waters KP-ABE secret key parameter.
 */
public class KPABERW13SecretKeySerParameter extends PairingKeySerParameter {
    private final AccessControlParameter accessControlParameter;

    private transient Map<String, Element> K0s;
    private final Map<String, byte[]> byteArraysK0s;

    private transient Map<String, Element> K1s;
    private final Map<String, byte[]> byteArraysK1s;

    private transient Map<String, Element> K2s;
    private final Map<String, byte[]> byteArraysK2s;

    public KPABERW13SecretKeySerParameter(PairingParameters pairingParameters, AccessControlParameter accessControlParameter,
                                          Map<String, Element> K0s, Map<String, Element> K1s, Map<String, Element> K2s) {
        super(true, pairingParameters);
        this.accessControlParameter = accessControlParameter;

        this.K0s = new HashMap<String, Element>();
        this.byteArraysK0s = new HashMap<String, byte[]>();
        this.K1s = new HashMap<String, Element>();
        this.byteArraysK1s = new HashMap<String, byte[]>();
        this.K2s = new HashMap<String, Element>();
        this.byteArraysK2s = new HashMap<String, byte[]>();

        for (String rho : K0s.keySet()) {
            this.K0s.put(rho, K0s.get(rho).duplicate().getImmutable());
            this.byteArraysK0s.put(rho, K0s.get(rho).duplicate().getImmutable().toBytes());
            this.K1s.put(rho, K1s.get(rho).duplicate().getImmutable());
            this.byteArraysK1s.put(rho, K1s.get(rho).duplicate().getImmutable().toBytes());
            this.K2s.put(rho, K2s.get(rho).duplicate().getImmutable());
            this.byteArraysK2s.put(rho, K2s.get(rho).duplicate().getImmutable().toBytes());
        }
    }

    public AccessControlParameter getAccessControlParameter() { return this.accessControlParameter; }

    public String[] getRhos() { return this.K0s.keySet().toArray(new String[1]); }

    public Element getK0sAt(String rho) { return this.K0s.get(rho).duplicate(); }

    public Element getK1sAt(String rho) { return this.K1s.get(rho).duplicate(); }

    public Element getK2sAt(String rho) { return this.K2s.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABERW13SecretKeySerParameter) {
            KPABERW13SecretKeySerParameter that = (KPABERW13SecretKeySerParameter)anObject;
            //Compare access policy
            if (!this.accessControlParameter.equals(that.accessControlParameter)) {
                return false;
            }
            //Compare K0s
            if (!this.K0s.equals(that.K0s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysK0s, that.byteArraysK0s)) {
                return false;
            }
            //Compare K1s
            if (!this.K1s.equals(that.K1s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysK1s, that.byteArraysK1s)) {
                return false;
            }
            //Compare K2s
            if (!this.K2s.equals(that.K2s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysK2s, that.byteArraysK2s)) {
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
        this.K0s = new HashMap<String, Element>();
        this.K1s = new HashMap<String, Element>();
        this.K2s = new HashMap<String, Element>();
        for (String rho : this.byteArraysK0s.keySet()) {
            this.K0s.put(rho, pairing.getG1().newElementFromBytes(this.byteArraysK0s.get(rho)).getImmutable());
            this.K1s.put(rho, pairing.getG1().newElementFromBytes(this.byteArraysK1s.get(rho)).getImmutable());
            this.K2s.put(rho, pairing.getG1().newElementFromBytes(this.byteArraysK2s.get(rho)).getImmutable());
        }
    }
}