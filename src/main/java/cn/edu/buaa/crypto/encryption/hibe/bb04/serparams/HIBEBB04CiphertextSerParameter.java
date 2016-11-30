package cn.edu.buaa.crypto.encryption.hibe.bb04.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Boneh-Boyen HIBE ciphertext parameter.
 */
public class HIBEBB04CiphertextSerParameter extends HIBEBB04HeaderSerParameter {
    private transient Element A;
    private final byte[] byteArrayA;



    public HIBEBB04CiphertextSerParameter(PairingParameters pairingParameters, Element A, Element B, Element[] Cs) {
        super(pairingParameters, B, Cs);

        this.A = A.getImmutable();
        this.byteArrayA = this.A.toBytes();
    }

    public Element getA() { return this.A.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04CiphertextSerParameter) {
            HIBEBB04CiphertextSerParameter that = (HIBEBB04CiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.A, that.getA())
                    && Arrays.equals(this.byteArrayA, that.byteArrayA)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.A = pairing.getGT().newElementFromBytes(this.byteArrayA).getImmutable();
    }
}
