package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingCiphertextParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04CiphertextParameters extends PairingCiphertextParameters {

    private int length;
    private Element B;
    private Element[] Cs;

    public HIBEBB04CiphertextParameters(PairingParameters pairingParameters, int length, Element B, Element[] Cs) {
        super(pairingParameters);
        this.length = length;
        this.B = B.getImmutable();
        this.Cs = ElementUtils.cloneImmutable(Cs);
    }

    public int getLength() { return this.length; }

    public Element getB() { return this.B; }

    public Element getCsAt(int index) { return this.Cs[index]; }
}
