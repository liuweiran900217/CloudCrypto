package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class CPABERW13ReEncHeaderSerParameter extends PairingCipherSerParameter {

    protected transient Element C0_;
    protected final byte[] byteArrayC0_;

    protected transient Element C1_;
    protected final byte[] byteArrayC1_;

    protected transient Element C2_;
    protected final byte[] byteArrayC2_;

    protected transient Element C3_;
    protected final byte[] byteArrayC3_;

    public CPABERW13ReEncHeaderSerParameter(PairingParameters pairingParameters, Element C0_,
                                            Element C1_, Element C2_, Element C3_) {
        super(pairingParameters);

        this.C0_ = C0_.getImmutable();
        this.byteArrayC0_ = this.C0_.toBytes();

        this.C1_ = C1_.getImmutable();
        this.byteArrayC1_ = this.C1_.toBytes();

        this.C2_ = C2_.getImmutable();
        this.byteArrayC2_ = this.C2_.toBytes();

        this.C3_ = C3_.getImmutable();
        this.byteArrayC3_ = this.C3_.toBytes();
    }

    public Element getC0_() { return this.C0_.duplicate(); }

    public Element getC1_() { return this.C1_.duplicate(); }

    public Element getC2_() { return this.C2_.duplicate(); }

    public Element getC3_() { return this.C3_.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13ReEncHeaderSerParameter) {
            CPABERW13ReEncHeaderSerParameter that = (CPABERW13ReEncHeaderSerParameter)anObject;
            //Compare C0_
            if (!PairingUtils.isEqualElement(this.C0_, that.C0_)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0_, that.byteArrayC0_)) {
                return false;
            }
            //Compare C1_
            if (!PairingUtils.isEqualElement(this.C1_, that.C1_)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC1_, that.byteArrayC1_)) {
                return false;
            }
            //Compare C2_
            if (!PairingUtils.isEqualElement(this.C2_, that.C2_)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC2_, that.byteArrayC2_)) {
                return false;
            }
            //Compare C3_
            if (!PairingUtils.isEqualElement(this.C3_, that.C3_)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayC3_, that.byteArrayC3_)) {
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
        this.C0_ = pairing.getG1().newElementFromBytes(this.byteArrayC0_).getImmutable();
        this.C1_ = pairing.getG1().newElementFromBytes(this.byteArrayC1_).getImmutable();
        this.C2_ = pairing.getG1().newElementFromBytes(this.byteArrayC2_).getImmutable();
        this.C3_ = pairing.getG1().newElementFromBytes(this.byteArrayC3_).getImmutable();
    }
}
