package cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams;

import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aHeaderSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE header parameter.
 */
public class IBEBF01bHeaderSerParameter extends IBEBF01aHeaderSerParameter {
    private transient Element V;
    private final byte[] byteArrayV;

    public IBEBF01bHeaderSerParameter(PairingParameters pairingParameters, Element U, Element V) {
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
        if (anObject instanceof IBEBF01bHeaderSerParameter) {
            IBEBF01bHeaderSerParameter that = (IBEBF01bHeaderSerParameter) anObject;
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
