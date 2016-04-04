package cn.edu.buaa.crypto.encryption.hibe.bbg05.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2015/11/3.
 */
public class HIBEBBG05CiphertextParameters extends PairingCiphertextParameters {
    private final int length;
    private final Element B;
    private final Element C;

    public HIBEBBG05CiphertextParameters(PairingParameters pairingParameters, int length, Element B, Element C) {
        super(pairingParameters);
        this.length = length;
        this.B = B.getImmutable();
        this.C = C.getImmutable();
    }

    public int getLength() { return this.length; }

    public Element getB() { return this.B.duplicate(); }

    public Element getC() { return this.C.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBBG05CiphertextParameters) {
            HIBEBBG05CiphertextParameters that = (HIBEBBG05CiphertextParameters)anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compare B
            if (!Utils.isEqualElement(this.B, that.getB())){
                return false;
            }
            //Compare C
            if (!Utils.isEqualElement(this.C, that.getC())){
                return false;
            }
            return true;
        }
        return false;
    }
}
