package cn.edu.buaa.crypto.encryption.ibe.LW10.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
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
            if (!Utils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            //Compare g
            if (!Utils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare h
            if (!Utils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            //Compare eggAlpha
            if (!Utils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            return true;
        }
        return false;
    }
}
