package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams.CPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE header parameter.
 */
public class CPABEHW14HeaderSerParameter extends CPABERW13HeaderSerParameter {
    private transient Map<String, Element> C4s;
    private final byte[][] byteArraysC4s;

    private transient Map<String, Element> C5s;
    private final byte[][] byteArraysC5s;

    public CPABEHW14HeaderSerParameter(PairingParameters pairingParameters, Element C0,
                                       Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s,
                                       Map<String, Element> C4s, Map<String, Element> C5s) {
        super(pairingParameters, C0, C1s, C2s, C3s);

        this.C4s = new HashMap<String, Element>();
        this.byteArraysC4s = new byte[rhos.length][];
        this.C5s = new HashMap<String, Element>();
        this.byteArraysC5s = new byte[rhos.length][];

        for (int i = 0; i < rhos.length; i++) {
            Element C4 = C4s.get(rhos[i]).duplicate().getImmutable();
            this.C4s.put(rhos[i], C4);
            this.byteArraysC4s[i] = C4.toBytes();

            Element C5 = C5s.get(rhos[i]).duplicate().getImmutable();
            this.C5s.put(rhos[i], C5);
            this.byteArraysC5s[i] = C5.toBytes();
        }
    }

    public Map<String, Element> getC4s() { return this.C4s; }

    public Element getC4sAt(String rho) { return this.C4s.get(rho).duplicate(); }

    public Map<String, Element> getC5s() { return this.C5s; }

    public Element getC5sAt(String rho) { return this.C5s.get(rho).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEHW14HeaderSerParameter) {
            CPABEHW14HeaderSerParameter that = (CPABEHW14HeaderSerParameter)anObject;
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
            //Compare super class
            return super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C4s = new HashMap<String, Element>();
        this.C5s = new HashMap<String, Element>();
        for (int i = 0; i < this.rhos.length; i++) {
            this.C4s.put(this.rhos[i], pairing.getZr().newElementFromBytes(this.byteArraysC4s[i]).getImmutable());
            this.C5s.put(this.rhos[i], pairing.getZr().newElementFromBytes(this.byteArraysC5s[i]).getImmutable());
        }
    }
}
