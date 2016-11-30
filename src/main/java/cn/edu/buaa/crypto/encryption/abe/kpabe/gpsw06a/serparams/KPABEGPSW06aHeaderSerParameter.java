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
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE header parameter.
 */
public class KPABEGPSW06aHeaderSerParameter extends PairingCipherSerParameter {
    private transient Map<String, Element> Es;
    private final Map<String, byte[]> byteArraysEs;

    public KPABEGPSW06aHeaderSerParameter(PairingParameters pairingParameters, Map<String, Element> Es) {
        super(pairingParameters);

        this.Es = new HashMap<String, Element>();
        this.byteArraysEs = new HashMap<String, byte[]>();
        for (String attribute : Es.keySet()) {
            Element E = Es.get(attribute).duplicate().getImmutable();
            this.Es.put(attribute, E);
            this.byteArraysEs.put(attribute, E.toBytes());
        }
    }

    public Element getEsAt(String attribute) { return this.Es.get(attribute).duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aHeaderSerParameter) {
            KPABEGPSW06aHeaderSerParameter that = (KPABEGPSW06aHeaderSerParameter)anObject;
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
        this.Es = new HashMap<String, Element>();
        for (String attribute : this.byteArraysEs.keySet()) {
            this.Es.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysEs.get(attribute)).getImmutable());
        }
    }
}
