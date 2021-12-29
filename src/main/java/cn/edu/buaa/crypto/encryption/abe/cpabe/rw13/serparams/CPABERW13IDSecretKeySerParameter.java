package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class CPABERW13IDSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element K0;
    private final byte[] byteArrayK0;

    private transient Element K1;
    private final byte[] byteArrayK1;

    public CPABERW13IDSecretKeySerParameter(PairingParameters pairingParameters,
                                            Element K0, Element K1) {
        super(true, pairingParameters);

        this.K0 = K0.getImmutable();
        this.byteArrayK0 = this.K0.toBytes();

        this.K1 = K1.getImmutable();
        this.byteArrayK1 = this.K1.toBytes();
    }

    public Element getK0() { return this.K0.duplicate(); }

    public Element getK1() { return this.K1.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13IDSecretKeySerParameter) {
            CPABERW13IDSecretKeySerParameter that = (CPABERW13IDSecretKeySerParameter)anObject;
            //Compare K0
            if (!PairingUtils.isEqualElement(this.K0, that.K0)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK0, that.byteArrayK0)) {
                return false;
            }
            //Compare k1
            if (!PairingUtils.isEqualElement(this.K1, that.K1)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayK1, that.byteArrayK1)) {
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
        this.K0 = pairing.getG1().newElementFromBytes(this.byteArrayK0);
        this.K1 = pairing.getG1().newElementFromBytes(this.byteArrayK1);
    }
}
