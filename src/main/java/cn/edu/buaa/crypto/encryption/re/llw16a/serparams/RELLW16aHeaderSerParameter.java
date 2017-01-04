package cn.edu.buaa.crypto.encryption.re.llw16a.serparams;

import cn.edu.buaa.crypto.encryption.re.lsw10a.serparams.RELSW10aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/4.
 *
 * Liu-Liu-Wu-16 CPA-secure RE header parameter.
 */
public class RELLW16aHeaderSerParameter extends RELSW10aHeaderSerParameter {
    private transient Map<String, Element> C3s;
    private final Map<String, byte[]> byteArraysC3s;

    public RELLW16aHeaderSerParameter(
            PairingParameters pairingParameters, Element C0,
            Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s) {
        super(pairingParameters, C0, C1s, C2s);

        this.C3s = new HashMap<String, Element>();
        this.byteArraysC3s = new HashMap<String, byte[]>();

        for (String revokeId : C1s.keySet()) {
            this.C3s.put(revokeId, C3s.get(revokeId).duplicate().getImmutable());
            this.byteArraysC3s.put(revokeId, C3s.get(revokeId).duplicate().getImmutable().toBytes());
        }
    }

    public Element getC3sAt(String revokeId) { return this.C3s.get(revokeId).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELLW16aHeaderSerParameter) {
            RELLW16aHeaderSerParameter that = (RELLW16aHeaderSerParameter) anObject;
            //Compare C3s
            if (!this.C3s.equals(that.C3s)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysC3s, that.byteArraysC3s)) {
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
        for (String revokeId : this.byteArraysC3s.keySet()) {
            this.C3s.put(revokeId, pairing.getG1().newElementFromBytes(this.byteArraysC3s.get(revokeId)).getImmutable());
            this.C3s.put(revokeId, pairing.getG1().newElementFromBytes(this.byteArraysC3s.get(revokeId)).getImmutable());
        }
    }
}
