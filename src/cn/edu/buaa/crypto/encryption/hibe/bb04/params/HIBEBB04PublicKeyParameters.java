package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04PublicKeyParameters extends PairingKeyParameters {

    private int maxLength;
    private Element g;
    private Element g1;
    private Element g2;
    private Element[] h;

    public HIBEBB04PublicKeyParameters(PairingParameters parameters, Element g, Element g1, Element g2, Element[] h) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.g1 = g1.getImmutable();
        this.g2 = g2.getImmutable();

        this.h = ElementUtils.cloneImmutable(h);
        this.maxLength = h.length;
    }

    public Element getG() { return this.g; }

    public Element getG1() { return this.g1; }

    public Element getG2() { return this.g2; }

    public Element[] getHs() { return Arrays.copyOf(this.h, this.h.length); }

    public Element getHsAt(int index) {
        return this.h[index];
    }

    public int getMaxLength() { return this.maxLength; }
}
