package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles master secret key parameter.
 */
public class KPABEGPSW06bMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element y;
    private final byte[] byteArrayY;

    public KPABEGPSW06bMasterSecretKeySerParameter(PairingParameters pairingParameters, Element y) {
        super(true, pairingParameters);

        this.y = y.getImmutable();
        this.byteArrayY = this.y.toBytes();
    }

    public Element getY() { return this.y.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06bMasterSecretKeySerParameter) {
            KPABEGPSW06bMasterSecretKeySerParameter that = (KPABEGPSW06bMasterSecretKeySerParameter)anObject;
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
        this.y = pairing.getZr().newElementFromBytes(this.byteArrayY).getImmutable();
    }
}