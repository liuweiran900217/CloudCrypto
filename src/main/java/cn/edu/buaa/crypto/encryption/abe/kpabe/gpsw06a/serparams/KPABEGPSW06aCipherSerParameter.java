package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

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
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE ciphertext parameter.
 */
public class KPABEGPSW06aCipherSerParameter extends PairingCipherSerParameter {
    private transient Element EPrime;
    private final byte[] byteArrayEPrime;

    private transient Map<String, Element> Es;
    private final Map<String, byte[]> byteArraysEs;

    public KPABEGPSW06aCipherSerParameter(PairingParameters pairingParameters, Element EPrime, Map<String, Element> Es) {
        super(pairingParameters);
        this.EPrime = EPrime.getImmutable();
        this.byteArrayEPrime = this.EPrime.toBytes();

        this.Es = new HashMap<String, Element>();
        this.byteArraysEs = new HashMap<String, byte[]>();
        for (String attribute : Es.keySet()) {
            Element E = Es.get(attribute).duplicate().getImmutable();
            this.Es.put(attribute, E);
            this.byteArraysEs.put(attribute, E.toBytes());
        }
    }

    public Element getEsAt(String attribute) { return this.Es.get(attribute).duplicate(); }

    public Element getEPrime() { return this.EPrime.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aCipherSerParameter) {
            KPABEGPSW06aCipherSerParameter that = (KPABEGPSW06aCipherSerParameter)anObject;
            //Compare EPrime
            if (!PairingUtils.isEqualElement(this.EPrime, that.EPrime)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayEPrime, that.byteArrayEPrime)) {
                return false;
            }
            //Compare Es
            if (!this.Es.equals(that.Es)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysEs, that.byteArraysEs)) {
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
        this.EPrime = pairing.getGT().newElementFromBytes(this.byteArrayEPrime);
        this.Es = new HashMap<String, Element>();
        for (String attribute : this.byteArraysEs.keySet()) {
            this.Es.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysEs.get(attribute)).getImmutable());
        }
    }
}
