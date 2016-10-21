package cn.edu.buaa.crypto.encryption.ibe.lw10.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/5/6.
 * Modified by Weiran Liu on 16/5/16.
 */
public class IBELW10PublicKeyParameters extends PairingKeyParameters {

    private final Element u;
    private final Element g;
    private final Element h;
    private final Element eggAlpha;

    public IBELW10PublicKeyParameters(PairingParameters parameters, Element u, Element g, Element h, Element eggAlpha) {
        super(false, parameters);

        this.u = u.getImmutable();
        this.g = g.getImmutable();
        this.h = h.getImmutable();
        this.eggAlpha = eggAlpha.getImmutable();
    }

    public Element getU() { return this.u.duplicate(); }

    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10PublicKeyParameters) {
            IBELW10PublicKeyParameters that = (IBELW10PublicKeyParameters)anObject;
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
