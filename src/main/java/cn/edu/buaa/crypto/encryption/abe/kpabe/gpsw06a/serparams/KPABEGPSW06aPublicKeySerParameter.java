package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE public key parameter.
 */
public class KPABEGPSW06aPublicKeySerParameter extends PairingKeySerParameter {

    private final int maxAttributesNum;

    public transient Element g;
    private final byte[] byteArrayG;

    private transient Element[] Ts;
    private final byte[][] byteArraysTs;

    private transient Element Y;
    private final byte[] byteArrayY;

    public KPABEGPSW06aPublicKeySerParameter(PairingParameters parameters, Element g, Element[] Ts, Element Y) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.Ts = ElementUtils.cloneImmutable(Ts);
        this.byteArraysTs = PairingUtils.GetElementArrayBytes(this.Ts);

        this.Y = Y.getImmutable();
        this.byteArrayY = this.Y.toBytes();

        this.maxAttributesNum = this.Ts.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getTsAt(int index) { return this.Ts[index].duplicate(); }

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
            if (!PairingUtils.isEqualElementArray(this.Ts, that.Ts)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysTs, that.byteArraysTs)) {
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
        this.Ts = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysTs, PairingUtils.PairingGroupType.G1);
        this.Y = pairing.getGT().newElementFromBytes(this.byteArrayY);
    }
}
