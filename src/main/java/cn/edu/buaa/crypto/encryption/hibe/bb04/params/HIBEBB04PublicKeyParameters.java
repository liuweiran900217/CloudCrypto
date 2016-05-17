package cn.edu.buaa.crypto.encryption.hibe.bb04.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04PublicKeyParameters extends PairingKeyParameters {

    private final int maxLength;
    private final Element g;
    private final Element g1;
    private final Element g2;
    private final Element[] hs;

    public HIBEBB04PublicKeyParameters(PairingParameters parameters, Element g, Element g1, Element g2, Element[] hs) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.g1 = g1.getImmutable();
        this.g2 = g2.getImmutable();

        this.hs = ElementUtils.cloneImmutable(hs);
        this.maxLength = hs.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() { return this.g1.duplicate(); }

    public Element getG2() { return this.g2.duplicate(); }

    public Element[] getHs() { return Arrays.copyOf(this.hs, this.hs.length); }

    public Element getHsAt(int index) {
        return this.hs[index].duplicate();
    }

    public int getMaxLength() { return this.maxLength; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04PublicKeyParameters) {
            HIBEBB04PublicKeyParameters that = (HIBEBB04PublicKeyParameters)anObject;
            //Compare maxLength
            if (this.maxLength != that.getMaxLength()) {
                return false;
            }
            //Compare g
            if (!Utils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare g1
            if (!Utils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            //Compare g2
            if (!Utils.isEqualElement(this.g2, that.getG2())) {
                return false;
            }
            //Compare hs
            if (!Utils.isEqualElementArray(this.hs, that.getHs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
