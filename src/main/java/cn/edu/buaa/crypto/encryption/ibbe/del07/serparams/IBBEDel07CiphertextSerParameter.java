package cn.edu.buaa.crypto.encryption.ibbe.del07.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/8/24.
 *
 * Ciphertext Parameters for Delerablée IBBE scheme.
 */
public class IBBEDel07CiphertextSerParameter extends PairingCipherSerParameter {
    private transient Element C1;
    private final byte[] byteArrayC1;

    private transient Element C2;
    private final byte[] byteArrayC2;

    public IBBEDel07CiphertextSerParameter(PairingParameters pairingParameters, Element C1, Element C2) {
        super(pairingParameters);
        this.C1 = C1.getImmutable();
        this.byteArrayC1 = this.C1.toBytes();

        this.C2 = C2.getImmutable();
        this.byteArrayC2 = this.C2.toBytes();
    }

    public Element getC1() { return this.C1.duplicate(); }

    public Element getC2() { return this.C2.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBBEDel07CiphertextSerParameter) {
            IBBEDel07CiphertextSerParameter that = (IBBEDel07CiphertextSerParameter)anObject;
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
        this.C1 = pairing.getG1().newElementFromBytes(this.byteArrayC1).getImmutable();
        this.C2 = pairing.getG1().newElementFromBytes(this.byteArrayC2).getImmutable();
    }
}
