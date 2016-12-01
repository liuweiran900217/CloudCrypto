package cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE header parameter.
 */
public class IBEGen06aCiphertextSerParameter extends IBEGen06aHeaderSerParameter {
    private transient Element w;
    private final byte[] byteArrayW;

    public IBEGen06aCiphertextSerParameter(PairingParameters pairingParameters, Element u, Element v, Element w) {
        super(pairingParameters, u, v);

        this.w = w.getImmutable();
        this.byteArrayW = this.w.toBytes();
    }

    public Element getW() { return this.w.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEGen06aCiphertextSerParameter) {
            IBEGen06aCiphertextSerParameter that = (IBEGen06aCiphertextSerParameter) anObject;
            //Compare w
            return PairingUtils.isEqualElement(this.w, that.w)
                    && Arrays.equals(this.byteArrayW, that.byteArrayW)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.w = pairing.getGT().newElementFromBytes(this.byteArrayW).getImmutable();
    }
}
