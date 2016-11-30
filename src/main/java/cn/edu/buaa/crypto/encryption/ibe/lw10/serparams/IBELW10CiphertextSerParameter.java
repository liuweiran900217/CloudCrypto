package cn.edu.buaa.crypto.encryption.ibe.lw10.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE ciphertext parameter.
 */
public class IBELW10CiphertextSerParameter extends IBELW10HeaderSerParameter {
    private transient Element C0;
    private final byte[] byteArrayC0;

    public IBELW10CiphertextSerParameter(PairingParameters pairingParameters, Element C0, Element C1, Element C2) {
        super(pairingParameters, C1, C2);
        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();
    }

    public Element getC0() { return this.C0.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10CiphertextSerParameter) {
            IBELW10CiphertextSerParameter that = (IBELW10CiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C0, that.getC0())
                    && Arrays.equals(this.byteArrayC0, that.byteArrayC0)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C0 = pairing.getGT().newElementFromBytes(this.byteArrayC0).getImmutable();
    }
}
