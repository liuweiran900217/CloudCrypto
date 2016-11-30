package cn.edu.buaa.crypto.encryption.abe.kpabe.gpsw06b.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/11/21.
 *
 * Goyal-Pandey-Sahai-Waters large-universe KP-ABE with random oracles ciphertext parameter.
 */
public class KPABEGPSW06bCiphertextSerParameter extends KPABEGPSW06bHeaderSerParameter {
    private transient Element E1;
    private final byte[] byteArrayE1;

    public KPABEGPSW06bCiphertextSerParameter(PairingParameters pairingParameters, Element E1, Element E2, Map<String, Element> Es) {
        super(pairingParameters, E2, Es);
        this.E1 = E1.getImmutable();
        this.byteArrayE1 = this.E1.toBytes();
    }

    public Element getE1() { return this.E1.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABEGPSW06bCiphertextSerParameter) {
            KPABEGPSW06bCiphertextSerParameter that = (KPABEGPSW06bCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.E1, that.E1)
                    && Arrays.equals(this.byteArrayE1, that.byteArrayE1)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.E1 = pairing.getGT().newElementFromBytes(this.byteArrayE1);
    }
}
