package cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE ciphertext parameter.
 */
public class IBEBF01bCiphertextSerParameter extends IBEBF01bHeaderSerParameter {
    private transient Element W;
    private final byte[] byteArrayW;

    public IBEBF01bCiphertextSerParameter(PairingParameters pairingParameters, Element U, Element V, Element W) {
        super(pairingParameters, U, V);
        this.W = W.getImmutable();
        this.byteArrayW = this.W.toBytes();
    }

    public Element getW() { return this.W.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEBF01bCiphertextSerParameter) {
            IBEBF01bCiphertextSerParameter that = (IBEBF01bCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.W, that.W)
                    && Arrays.equals(this.byteArrayW, that.byteArrayW)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.W = pairing.getGT().newElementFromBytes(this.byteArrayW).getImmutable();
    }
}
