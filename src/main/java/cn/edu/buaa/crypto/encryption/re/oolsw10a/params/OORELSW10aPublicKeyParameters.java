package cn.edu.buaa.crypto.encryption.re.oolsw10a.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.chameleonhash.CHEngine;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/4/5.
 */
public class OORELSW10aPublicKeyParameters extends PairingKeyParameters {
    private CHEngine chEngine;
    private final Element g;
    private final Element gb;
    private final Element gb2;
    private final Element hb;
    private final Element eggAlpha;

    public OORELSW10aPublicKeyParameters(PairingParameters parameters,
                                       Element g, Element g_b, Element g_b2, Element h_b, Element e_g_g_alpha, CHEngine chEngine) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.gb = g_b.getImmutable();
        this.gb2 = g_b2.getImmutable();
        this.hb = h_b.getImmutable();
        this.eggAlpha = e_g_g_alpha.getImmutable();
        this.chEngine = chEngine;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getGb() { return this.gb.duplicate(); }

    public Element getGb2() { return this.gb2.duplicate(); }

    public Element getHb() { return this.hb.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public CHEngine getCHEngine() { return this.chEngine; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof OORELSW10aPublicKeyParameters) {
            OORELSW10aPublicKeyParameters that = (OORELSW10aPublicKeyParameters) anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare g_b
            if (!PairingUtils.isEqualElement(this.gb, that.getGb())) {
                return false;
            }
            //Compare g_b2
            if (!PairingUtils.isEqualElement(this.gb2, that.getGb2())) {
                return false;
            }
            //Compare h_b
            if (!PairingUtils.isEqualElement(this.hb, that.getHb())) {
                return false;
            }
            //Compare e_g_g_alpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            if (!this.chEngine.getName().equals(that.getCHEngine().getName())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
