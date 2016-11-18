package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/11/17.
 *
 * Goyal-Pandey-Sahai-Waters small-universe KP-ABE ciphertext parameter.
 */
public class KPABEGPSW06aCipherSerParameter extends PairingCipherSerParameter {
    private transient Element[] Es;
    private final byte[][] byteArraysEs;

    public KPABEGPSW06aCipherSerParameter(PairingParameters pairingParameters, Element[] Es) {
        super(pairingParameters);

        this.Es = ElementUtils.cloneImmutable(Es);
        this.byteArraysEs = PairingUtils.GetElementArrayBytes(this.Es);
    }

    public Element[] getEs() { return ElementUtils.cloneImmutable(Es); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06aCipherSerParameter) {
            KPABEGPSW06aCipherSerParameter that = (KPABEGPSW06aCipherSerParameter)anObject;
            //Compare Es
            if (!PairingUtils.isEqualElementArray(this.Es, that.Es)){
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysEs, that.byteArraysEs)) {
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
        this.Es = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysEs, PairingUtils.PairingGroupType.G1);
    }
}
