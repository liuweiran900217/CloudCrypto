package cn.edu.buaa.crypto.encryption.abe.kpabe.rw13.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/7/21.
 */
public class KPABERW13PublicKeyParameters extends PairingKeyParameters {
    private final Element g;
    private final Element u;
    private final Element h;
    private final Element w;
    private final Element eggAlpha;

    public KPABERW13PublicKeyParameters(PairingParameters parameters, Element g, Element u, Element h, Element w, Element eggAlpha) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.u = u.getImmutable();
        this.h = h.getImmutable();
        this.w = w.getImmutable();
        this.eggAlpha = eggAlpha.getImmutable();
    }

    public Element getG() {
        return this.g.duplicate();
    }

    public Element getU() {
        return this.u.duplicate();
    }

    public Element getH() {
        return this.h.duplicate();
    }

    public Element getW() {
        return this.w.duplicate();
    }

    public Element getEggAlpha() {
        return this.eggAlpha.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof KPABERW13PublicKeyParameters) {
            KPABERW13PublicKeyParameters that = (KPABERW13PublicKeyParameters)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            //Compare w
            if (!PairingUtils.isEqualElement(this.w, that.getW())) {
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
