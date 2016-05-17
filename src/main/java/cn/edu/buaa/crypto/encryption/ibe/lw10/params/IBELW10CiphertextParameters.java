package cn.edu.buaa.crypto.encryption.ibe.lw10.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10CiphertextParameters extends PairingCiphertextParameters {

    private final Element C1;
    private final Element C2;

    public IBELW10CiphertextParameters(PairingParameters pairingParameters, Element C1, Element C2) {
        super(pairingParameters);
        this.C1 = C1.getImmutable();
        this.C2 = C2.getImmutable();
    }

    public Element getC1() { return this.C1.duplicate(); }

    public Element getC2() { return this.C2.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10CiphertextParameters) {
            IBELW10CiphertextParameters that = (IBELW10CiphertextParameters)anObject;
            //Compare C1
            if (!Utils.isEqualElement(this.C1, that.getC1())){
                return false;
            }
            //Compare C2
            if (!Utils.isEqualElement(this.C2, that.getC2())){
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
