package cn.edu.buaa.crypto.encryption.hibbe.llw14.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 *
 * Liu-Liu-Wu composite-order HIBBE ciphertext parameters.
 */
public class HIBBELLW14CiphertextSerParameter extends PairingCipherSerParameter {
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Element C1;
    private final byte[] byteArrayC1;

    private transient Element C2;
    private final byte[] byteArrayC2;

    public HIBBELLW14CiphertextSerParameter(PairingParameters pairingParameters, Element C0, Element C1, Element C2) {
        super(pairingParameters);
        this.C0 = C0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1 = C1.getImmutable();
        this.byteArrayC1 = this.C1.toBytes();

        this.C2 = C2.getImmutable();
        this.byteArrayC2 = this.C2.toBytes();
    }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1() { return this.C1.duplicate(); }

    public Element getC2() { return this.C2.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW14CiphertextSerParameter) {
            HIBBELLW14CiphertextSerParameter that = (HIBBELLW14CiphertextSerParameter)anObject;
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                return false;
            }
            //Compare C1
            if (!PairingUtils.isEqualElement(this.C1, that.getC1())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC1, that.byteArrayC1)) {
                return false;
            }
            //Compare C2
            if (!PairingUtils.isEqualElement(this.C2, that.getC2())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC2, that.byteArrayC2)) {
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
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
        this.C2 = pairing.getGT().newElementFromBytes(this.byteArrayC2).getImmutable();
    }
}
