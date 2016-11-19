package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

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
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE master secret key parameter.
 */
public class KPABEGPSW06aMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Map<String, Element> ts;
    private final Map<String, byte[]> byteArraysTs;

    private transient Element y;
    private final byte[] byteArrayY;

    public KPABEGPSW06aMasterSecretKeySerParameter(PairingParameters pairingParameters, Map<String, Element> ts, Element y) {
        super(true, pairingParameters);

        this.ts = new HashMap<String, Element>();
        this.byteArraysTs = new HashMap<String, byte[]>();
        for (String attribute : ts.keySet()) {
            Element elementAttribute = ts.get(attribute).duplicate().getImmutable();
            this.ts.put(attribute, elementAttribute);
            this.byteArraysTs.put(attribute, elementAttribute.toBytes());
        }

        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
    }

    public Element getTsAt(String attribute) { return this.ts.get(attribute).duplicate(); }

    public Element getY() { return this.y.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aMasterSecretKeySerParameter) {
            KPABEGPSW06aMasterSecretKeySerParameter that = (KPABEGPSW06aMasterSecretKeySerParameter)anObject;
            //compare g
            if (!this.ts.equals(that.ts)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysTs, that.byteArraysTs)) {
                return false;
            }
            //compare y
            if (!(PairingUtils.isEqualElement(this.y, that.y))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayY, that.byteArrayY)) {
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
        this.ts = new HashMap<String, Element>();
        for (String attribute : this.byteArraysTs.keySet()) {
            this.ts.put(attribute, pairing.getZr().newElementFromBytes(this.byteArraysTs.get(attribute)).getImmutable());
        }
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY).getImmutable();
    }
}
