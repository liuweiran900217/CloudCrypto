package cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE header parameter.
 */
public class IBEBF01aHeaderSerParameter extends PairingCipherSerParameter {
    private transient Element U;
    private final byte[] byteArrayU;

    public IBEBF01aHeaderSerParameter(PairingParameters pairingParameters, Element U) {
        super(pairingParameters);
        this.U = U.getImmutable();
        this.byteArrayU = this.U.toBytes();
    }

    public Element getU() { return this.U.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEBF01aHeaderSerParameter) {
            IBEBF01aHeaderSerParameter that = (IBEBF01aHeaderSerParameter)anObject;
            //Compare C1
            if (!PairingUtils.isEqualElement(this.U, that.U)){
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
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
        this.U = pairing.getG1().newElementFromBytes(this.byteArrayU).getImmutable();
    }
}
