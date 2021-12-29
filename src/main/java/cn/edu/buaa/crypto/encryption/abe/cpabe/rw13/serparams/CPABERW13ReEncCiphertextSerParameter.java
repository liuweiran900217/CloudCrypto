package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

public class CPABERW13ReEncCiphertextSerParameter extends CPABERW13ReEncHeaderSerParameter {

    private transient Element C_;
    private final byte[] byteArrayC_;

    public CPABERW13ReEncCiphertextSerParameter(PairingParameters pairingParameters,
                                                Element C_, Element C0_, Element C1_,
                                                Element C2_, Element C3_) {
        super(pairingParameters, C0_, C1_, C2_, C3_);

        this.C_ = C_.getImmutable();
        this.byteArrayC_ = this.C_.toBytes();
    }

    public Element getC_() { return this.C_.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13ReEncCiphertextSerParameter) {
            CPABERW13ReEncCiphertextSerParameter that = (CPABERW13ReEncCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.C_, that.C_)
                    && Arrays.equals(this.byteArrayC_, that.byteArrayC_)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.C_ = pairing.getGT().newElementFromBytes(this.byteArrayC_).getImmutable();
    }

}
