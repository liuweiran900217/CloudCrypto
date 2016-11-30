package cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE ciphertext parameter.
 */
public class IBEBF01aCiphertextSerParameter extends IBEBF01aHeaderSerParameter {
    private transient Element V;
    private final byte[] byteArrayV;

    public IBEBF01aCiphertextSerParameter(PairingParameters pairingParameters, Element U, Element V) {
        super(pairingParameters, U);
        this.V = V.getImmutable();
        this.byteArrayV = this.V.toBytes();
    }

    public Element getV() { return this.V.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEBF01aCiphertextSerParameter) {
            IBEBF01aCiphertextSerParameter that = (IBEBF01aCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.V, that.V)
                    && Arrays.equals(this.byteArrayV, that.byteArrayV)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.V = pairing.getGT().newElementFromBytes(this.byteArrayV).getImmutable();
    }
}
