package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

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
 * Created by Weiran Liu on 2016/4/4.
 *
 * Lewko-Sahai-Waters reovcation encryption header parameters.
 */
public class RELSW10aHeaderSerParameter extends PairingCipherSerParameter {
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Map<String, Element> C1s;
    private final Map<String, byte[]> byteArraysC1s;

    private transient Map<String, Element> C2s;
    private final Map<String, byte[]> byteArraysC2s;

    public RELSW10aHeaderSerParameter(PairingParameters pairingParameters, Element C0, Map<String, Element> C1s, Map<String, Element> C2s) {
        super(pairingParameters);

        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1s = new HashMap<String, Element>();
        this.byteArraysC1s = new HashMap<String, byte[]>();
        this.C2s = new HashMap<String, Element>();
        this.byteArraysC2s = new HashMap<String, byte[]>();
        for (String revokeId : C1s.keySet()) {
            this.C1s.put(revokeId, C1s.get(revokeId).duplicate().getImmutable());
            this.byteArraysC1s.put(revokeId, C1s.get(revokeId).duplicate().getImmutable().toBytes());
            this.C2s.put(revokeId, C2s.get(revokeId).duplicate().getImmutable());
            this.byteArraysC2s.put(revokeId, C2s.get(revokeId).duplicate().getImmutable().toBytes());
        }
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1sAt(String revokeId) { return this.C1s.get(revokeId).duplicate(); }

    public Element getC2sAt(String revokeId) { return this.C2s.get(revokeId).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aHeaderSerParameter) {
            RELSW10aHeaderSerParameter that = (RELSW10aHeaderSerParameter) anObject;
            //Compre C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1s = new HashMap<String, Element>();
        this.C2s = new HashMap<String, Element>();
        for (String revokeId : this.byteArraysC1s.keySet()) {
            this.C1s.put(revokeId, pairing.getG1().newElementFromBytes(this.byteArraysC1s.get(revokeId)).getImmutable());
            this.C2s.put(revokeId, pairing.getG1().newElementFromBytes(this.byteArraysC2s.get(revokeId)).getImmutable());
        }
    }
}
