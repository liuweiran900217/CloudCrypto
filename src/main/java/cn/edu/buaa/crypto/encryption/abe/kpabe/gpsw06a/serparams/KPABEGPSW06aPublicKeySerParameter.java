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
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key parameter.
 */
public class KPABEGPSW06aPublicKeySerParameter extends PairingKeySerParameter {

    private final int maxAttributesNum;

    public transient Element g;
    private final byte[] byteArrayG;

    private transient Map<String, Element> Ts;
    private final Map<String, byte[]> byteArraysTs;

    private transient Element Y;
    private final byte[] byteArrayY;

    public KPABEGPSW06aPublicKeySerParameter(PairingParameters parameters, Element g, Map<String, Element> Ts, Element Y) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.Ts = new HashMap<String, Element>();
        this.byteArraysTs = new HashMap<String, byte[]>();
        for (String attribute : Ts.keySet()) {
            Element T = Ts.get(attribute).duplicate().getImmutable();
            this.Ts.put(attribute, T);
            this.byteArraysTs.put(attribute, T.toBytes());
        }

        this.Y = Y.getImmutable();
        this.byteArrayY = this.Y.toBytes();

        this.maxAttributesNum = this.Ts.keySet().size();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getTsAt(String attribute) { return this.Ts.get(attribute).duplicate(); }

    public Element getY() { return this.Y.duplicate(); }

    public int getMaxAttributesNum() { return this.maxAttributesNum; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aPublicKeySerParameter) {
            KPABEGPSW06aPublicKeySerParameter that = (KPABEGPSW06aPublicKeySerParameter)anObject;
            //Compare maximal broadcast receivers
            if (this.maxAttributesNum != that.maxAttributesNum) {
                return false;
            }
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare Ts
            if (!this.Ts.equals(that.Ts)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysTs, that.byteArraysTs)) {
                return false;
            }
            //Compare Y
            if (!PairingUtils.isEqualElement(this.Y, that.Y)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG);
        this.Ts = new HashMap<String, Element>();
        for (String attribute : this.byteArraysTs.keySet()) {
            this.Ts.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysTs.get(attribute)));
        }
        this.Y = pairing.getGT().newElementFromBytes(this.byteArrayY);
    }
}
