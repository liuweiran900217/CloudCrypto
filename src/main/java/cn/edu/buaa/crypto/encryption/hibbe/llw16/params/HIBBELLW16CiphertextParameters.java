package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16CiphertextParameters extends PairingCiphertextParameters {
    private final Element C0;
    private final Element C1;

    public HIBBELLW16CiphertextParameters(PairingParameters pairingParameters, Element C0, Element C1) {
        super(pairingParameters);
        this.C0 = C0.getImmutable();
        this.C1 = C1.getImmutable();
    }

    public Element getC0() {
        return this.C0.duplicate();
    }

    public Element getC1() {
        return this.C1.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16CiphertextParameters) {
            HIBBELLW16CiphertextParameters that = (HIBBELLW16CiphertextParameters) anObject;
            //Compare C0
            if (!Utils.isEqualElement(this.C0, that.getC0())) {
                return false;
            }
            //Compare C1
            if (!Utils.isEqualElement(this.C1, that.getC1())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}