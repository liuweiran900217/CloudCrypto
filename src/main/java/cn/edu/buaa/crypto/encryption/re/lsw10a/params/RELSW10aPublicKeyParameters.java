package cn.edu.buaa.crypto.encryption.re.lsw10a.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/4/3.
 */
public class RELSW10aPublicKeyParameters extends PairingKeyParameters {
    private final Element g;
    private final Element gb;
    private final Element gb2;
    private final Element hb;
    private final Element eggAlpha;

    public RELSW10aPublicKeyParameters(PairingParameters parameters,
                                       Element g, Element g_b, Element g_b2, Element h_b, Element e_g_g_alpha) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.gb = g_b.getImmutable();
        this.gb2 = g_b2.getImmutable();
        this.hb = h_b.getImmutable();
        this.eggAlpha = e_g_g_alpha.getImmutable();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getGb() { return this.gb.duplicate(); }

    public Element getGb2() { return this.gb2.duplicate(); }

    public Element getHb() { return this.hb.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aPublicKeyParameters) {
            RELSW10aPublicKeyParameters that = (RELSW10aPublicKeyParameters) anObject;
            //Compare g
            if (!Utils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare g_b
            if (!Utils.isEqualElement(this.gb, that.getGb())) {
                return false;
            }
            //Compare g_b2
            if (!Utils.isEqualElement(this.gb2, that.getGb2())) {
                return false;
            }
            //Compare h_b
            if (!Utils.isEqualElement(this.hb, that.getHb())) {
                return false;
            }
            //Compare e_g_g_alpha
            if (!Utils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            return true;
        }
        return false;
    }
}
