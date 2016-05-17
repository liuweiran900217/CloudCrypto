package cn.edu.buaa.crypto.encryption.hibbe.llw14.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/16.
 */
public class HIBBELLW14PublicKeyParameters extends PairingKeyParameters {

    private final int maxUser;
    private final Element g;
    private final Element h;
    private final Element[] u;
    private final Element X3;
    private final Element eggAlpha;

    public HIBBELLW14PublicKeyParameters(PairingParameters parameters, Element g, Element h, Element[] u, Element X3, Element eggAlpha) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.h = h.getImmutable();
        this.u = ElementUtils.cloneImmutable(u);
        this.X3 = X3.getImmutable();
        this.eggAlpha = eggAlpha.getImmutable();
        this.maxUser = u.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element[] getUs() { return Arrays.copyOf(this.u, this.u.length); }

    public Element getUsAt(int index) {
        return this.u[index].duplicate();
    }

    public Element getX3() { return this.X3.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public int getMaxUser() { return this.maxUser; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW14PublicKeyParameters) {
            HIBBELLW14PublicKeyParameters that = (HIBBELLW14PublicKeyParameters)anObject;
            //Compare g
            if (!Utils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare h
            if (!Utils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            //Compare u
            if (!Utils.isEqualElementArray(this.u, that.getUs())) {
                return false;
            }
            //Compare X3
            if (!Utils.isEqualElement(this.X3, that.getX3())) {
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
