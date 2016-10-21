package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 2016/9/20.
 *
 * Ciphertext parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13CiphertextParameters extends PairingCiphertextParameters {
    private final int length;
    private final Element C0;
    private final Element[] C1s;
    private final Element[] C2s;
    private final Element[] C3s;

    public CPABERW13CiphertextParameters(PairingParameters pairingParameters, Element C0, Element[] C1s,
                                         Element[] C2s, Element[] C3s) {
        super(pairingParameters);
        this.length = C1s.length;
        this.C0 = C0.getImmutable();
        this.C1s = ElementUtils.cloneImmutable(C1s);
        this.C2s = ElementUtils.cloneImmutable(C2s);
        this.C3s = ElementUtils.cloneImmutable(C3s);
    }

    public int getLength() { return this.length; }

    public Element getC0() { return this.C0.duplicate(); }

    public Element getC1At(int index) { return this.C1s[index].duplicate(); }

    public Element[] getC1s() { return this.C1s; }

    public Element getC2At(int index) { return this.C2s[index].duplicate(); }

    public Element[] getC2s() { return this.C2s; }

    public Element getC3At(int index) { return this.C3s[index].duplicate(); }

    public Element[] getC3s() { return this.C3s; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13CiphertextParameters) {
            CPABERW13CiphertextParameters that = (CPABERW13CiphertextParameters)anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compare C0
            if (!PairingUtils.isEqualElement(this.C0, that.getC0())){
                return false;
            }
            //Compare C1s
            if (!PairingUtils.isEqualElementArray(this.C1s, that.getC1s())) {
                return false;
            }
            //Compare C2s
            if (!PairingUtils.isEqualElementArray(this.C2s, that.getC2s())) {
                return false;
            }
            //Compare C3s
            if (!PairingUtils.isEqualElementArray(this.C3s, that.getC3s())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
