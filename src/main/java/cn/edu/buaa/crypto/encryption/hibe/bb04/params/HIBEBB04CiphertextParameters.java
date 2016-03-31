package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04CiphertextParameters extends PairingCiphertextParameters {

    private final int length;
    private final Element B;
    private final Element[] Cs;

    public HIBEBB04CiphertextParameters(PairingParameters pairingParameters, int length, Element B, Element[] Cs) {
        super(pairingParameters);
        this.length = length;
        this.B = B.getImmutable();
        this.Cs = ElementUtils.cloneImmutable(Cs);
    }

    public int getLength() { return this.length; }

    public Element getB() { return this.B.duplicate(); }

    public Element getCsAt(int index) { return this.Cs[index].duplicate(); }

    public Element[] getCs() { return Arrays.copyOf(Cs, Cs.length); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04CiphertextParameters) {
            HIBEBB04CiphertextParameters that = (HIBEBB04CiphertextParameters)anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compare B
            if (!Utils.isEqualElement(this.B, that.getB())){
                return false;
            }
            //Compare Cs
            if (!Utils.isEqualElementArray(this.Cs, that.getCs())){
                return false;
            }
            return true;
        }
        return false;
    }
}
