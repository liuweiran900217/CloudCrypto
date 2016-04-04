package cn.edu.buaa.crypto.encryption.re.ls10_1.params;

import cn.edu.buaa.crypto.Utils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 16/4/3.
 */
public class RELS10_1PublicKeyParameters extends PairingKeyParameters {
    private final Element g;
    private final Element g_b;
    private final Element g_b2;
    private final Element h_b;
    private final Element e_g_g_alpha;

    public RELS10_1PublicKeyParameters(PairingParameters parameters,
                                       Element g, Element g_b, Element g_b2, Element h_b, Element e_g_g_alpha) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.g_b = g_b.getImmutable();
        this.g_b2 = g_b2.getImmutable();
        this.h_b = h_b.getImmutable();
        this.e_g_g_alpha = e_g_g_alpha.getImmutable();
    }

    public Element get_g() { return this.g.duplicate(); }

    public Element get_g_b() { return this.g_b.duplicate(); }

    public Element get_g_b2() { return this.g_b2.duplicate(); }

    public Element get_h_b() { return this.h_b.duplicate(); }

    public Element get_e_g_g_alpha() { return this.e_g_g_alpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELS10_1PublicKeyParameters) {
            RELS10_1PublicKeyParameters that = (RELS10_1PublicKeyParameters) anObject;
            //Compare g
            if (!Utils.isEqualElement(this.g, that.get_g())) {
                return false;
            }
            //Compare g_b
            if (!Utils.isEqualElement(this.g_b, that.get_g_b())) {
                return false;
            }
            //Compare g_b2
            if (!Utils.isEqualElement(this.g_b2, that.get_g_b2())) {
                return false;
            }
            //Compare h_b
            if (!Utils.isEqualElement(this.h_b, that.get_h_b())) {
                return false;
            }
            //Compare e_g_g_alpha
            if (!Utils.isEqualElement(this.e_g_g_alpha, that.get_e_g_g_alpha())) {
                return false;
            }
            return true;
        }
        return false;
    }
}
