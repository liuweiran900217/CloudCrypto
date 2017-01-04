package cn.edu.buaa.crypto.encryption.abe.kpabe.hw14.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.serparams.KPABERW13HeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 17/1/2.
 *
 * Hohenberger-Waters-14 CPA-secure OO-KP-ABE header parameter.
 */
public class KPABEHW14HeaderSerParameter extends KPABERW13HeaderSerParameter {
    private transient Map<String, Element> C3s;
    private final byte[][] byteArraysC3s;

    public KPABEHW14HeaderSerParameter(
            PairingParameters pairingParameters, Element C0,
            Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
        super(pairingParameters, C0, C1s, C2s);
        this.C3s = new HashMap<String, Element>();
        this.byteArraysC3s = new byte[attributes.length][];

        for (int i = 0; i < attributes.length; i++) {
            Element C3 = C3s.get(attributes[i]).duplicate().getImmutable();
            this.C3s.put(attributes[i], C3);
            this.byteArraysC3s[i] = C3.toBytes();
        }
    }

    public Map<String, Element> getC3s() { return this.C3s; }

    public Element getC3sAt(String attribute) { return this.C3s.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEHW14HeaderSerParameter) {
            KPABEHW14HeaderSerParameter that = (KPABEHW14HeaderSerParameter)anObject;
            //Compare C3s
            if (!this.C3s.equals(that.C3s)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC3s, that.byteArraysC3s)) {
                return false;
            }
            //Compare Pairing Parameters
            return super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C3s = new HashMap<String, Element>();
        for (int i = 0; i < this.attributes.length; i++) {
            this.C3s.put(this.attributes[i], pairing.getZr().newElementFromBytes(this.byteArraysC3s[i]).getImmutable());
        }
    }
}
