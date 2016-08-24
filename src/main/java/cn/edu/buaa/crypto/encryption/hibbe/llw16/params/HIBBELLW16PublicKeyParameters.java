package cn.edu.buaa.crypto.encryption.hibbe.llw16.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/5/17.
 */
public class HIBBELLW16PublicKeyParameters extends PairingKeyParameters {

    private final int maxUser;
    private final Element g;
    private final Element g1;
    private final Element g2;
    private final Element g3;
    private final Element[] u;

    public HIBBELLW16PublicKeyParameters(PairingParameters parameters, Element g, Element g1, Element g2, Element g3, Element[] u) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.g1 = g1.getImmutable();
        this.g2 = g2.getImmutable();
        this.g3 = g3.getImmutable();
        this.u = ElementUtils.cloneImmutable(u);
        this.maxUser = u.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() { return this.g1.duplicate(); }

    public Element getG2() { return this.g2.duplicate(); }

    public Element getG3() { return this.g3.duplicate(); }

    public Element[] getUs() { return Arrays.copyOf(this.u, this.u.length); }

    public Element getUsAt(int index) {
        return this.u[index].duplicate();
    }

    public int getMaxUser() { return this.maxUser; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBBELLW16PublicKeyParameters) {
            HIBBELLW16PublicKeyParameters that = (HIBBELLW16PublicKeyParameters)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.getG2())) {
                return false;
            }
            //Compare g3
            if (!PairingUtils.isEqualElement(this.g3, that.getG3())) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElementArray(this.u, that.getUs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

