package cn.edu.buaa.crypto.encryption.hibe.bbg05.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2015/11/3.
 *
 * Boneh-Boyen-Goh HIBE ciphertext parameter.
 */
public class HIBEBBG05CiphertextSerParameter extends PairingCipherSerParameter {
    private transient Element A;
    private final byte[] byteArrayA;

    private transient Element B;
    private final byte[] byteArrayB;

    private transient Element C;
    private final byte[] byteArrayC;

    public HIBEBBG05CiphertextSerParameter(PairingParameters pairingParameters, Element A, Element B, Element C) {
        super(pairingParameters);

        this.A = A.getImmutable();
        this.byteArrayA = this.A.toBytes();

        this.B = B.getImmutable();
        this.byteArrayB = this.B.toBytes();

        this.C = C.getImmutable();
        this.byteArrayC = this.C.toBytes();
    }

    public Element getA() { return this.A.duplicate(); }

    public Element getB() { return this.B.duplicate(); }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBBG05CiphertextSerParameter) {
            HIBEBBG05CiphertextSerParameter that = (HIBEBBG05CiphertextSerParameter)anObject;
            //Compare A
            if (!PairingUtils.isEqualElement(this.A, that.getA())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayA, that.byteArrayA)) {
                return false;
            }
            //Compare B
            if (!PairingUtils.isEqualElement(this.B, that.getB())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayB, that.byteArrayB)) {
                return false;
            }
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.getC())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
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
        this.A = pairing.getGT().newElementFromBytes(this.byteArrayA).getImmutable();
        this.B = pairing.getG1().newElementFromBytes(this.byteArrayB).getImmutable();
        this.C = pairing.getG1().newElementFromBytes(this.byteArrayC).getImmutable();
    }
}
