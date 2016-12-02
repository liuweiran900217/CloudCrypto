package cn.edu.buaa.crypto.encryption.be.bgw05.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE secret key parameter.
 */
public class BEBGW05SecretKeySerParameter extends PairingKeySerParameter {
    private final int index;

    private transient Element d;
    private final byte[] byteArrayD;

    public BEBGW05SecretKeySerParameter(PairingParameters pairingParameters, int index, Element d) {
        super(true, pairingParameters);

        this.index = index;
        this.d = d.getImmutable();
        this.byteArrayD = this.d.toBytes();
    }

    public int getIndex() {
        return this.index;
    }

    public Element getD() {
        return this.d.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof BEBGW05SecretKeySerParameter) {
            BEBGW05SecretKeySerParameter that = (BEBGW05SecretKeySerParameter)anObject;
            //Compare index
            if (this.index != that.index) {
                return false;
            }
            //Compare K2s
            if (!PairingUtils.isEqualElement(this.d, that.d)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
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
        this.d = pairing.getG1().newElementFromBytes(this.byteArrayD).getImmutable();
    }
}