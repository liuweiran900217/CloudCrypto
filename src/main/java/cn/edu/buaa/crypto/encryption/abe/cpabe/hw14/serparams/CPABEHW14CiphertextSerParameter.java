package cn.edu.buaa.crypto.encryption.abe.cpabe.hw14.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * Created by Weiran Liu on 2017/1/1.
 *
 * Hohenberger-Waters-14 OO-CP-ABE ciphertext parameter.
 */
public class CPABEHW14CiphertextSerParameter extends CPABEHW14HeaderSerParameter {
    private transient Element C;
    private final byte[] byteArrayC;

    public CPABEHW14CiphertextSerParameter(PairingParameters pairingParameters, Element C, Element C0,
                                           Map<String, Element> C1s, Map<String, Element> C2s, Map<String, Element> C3s,
                                           Map<String, Element> C4s, Map<String, Element> C5s) {
        super(pairingParameters, C0, C1s, C2s, C3s, C4s, C5s);

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABEHW14CiphertextSerParameter) {
            CPABEHW14CiphertextSerParameter that = (CPABEHW14CiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C, that.C)
                    && Arrays.equals(this.byteArrayC, that.byteArrayC)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C = pairing.getGT().newElementFromBytes(this.byteArrayC).getImmutable();
    }
}