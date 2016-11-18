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
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE master secret key parameter.
 */
public class KPABEGPSW06aMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element[] ts;
    private final byte[][] byteArraysTs;

    private transient Element y;
    private final byte[] byteArrayY;

    public KPABEGPSW06aMasterSecretKeySerParameter(PairingParameters pairingParameters, Element[] ts, Element y) {
        super(true, pairingParameters);
        this.ts = ElementUtils.cloneImmutable(ts);
        this.byteArraysTs = PairingUtils.GetElementArrayBytes(this.ts);

        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
    }

    public Element getTsAt(int index) { return this.ts[index].duplicate(); }

    public Element getY() { return this.y.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aMasterSecretKeySerParameter) {
            KPABEGPSW06aMasterSecretKeySerParameter that = (KPABEGPSW06aMasterSecretKeySerParameter)anObject;
            //compare g
            if (!(PairingUtils.isEqualElementArray(this.ts, that.ts))) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysTs, that.byteArraysTs)) {
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
        this.ts = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysTs, PairingUtils.PairingGroupType.Zr);
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY);
    }
}
