package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control public key parameters.
 */
public class RBACLLW15PublicKeyParameters extends PairingKeyParameters {

    private final int maxRoleNumber;
    private final Element g;
    private final Element g1;
    private final Element g2;
    private final Element g3;
    private final Element gh;

    //u0 is associated with the lifetime
    private final Element u0;
    //uv is associated with the verification attribute
    private final Element uv;
    private final Element[] u;

    public RBACLLW15PublicKeyParameters(PairingParameters parameters, Element g, Element g1, Element g2, Element g3,
                                        Element gh, Element u0, Element uv, Element[] u) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.g1 = g1.getImmutable();
        this.g2 = g2.getImmutable();
        this.g3 = g3.getImmutable();
        this.gh = gh.getImmutable();
        this.u0 = u0.getImmutable();
        this.uv = uv.getImmutable();
        this.u = ElementUtils.cloneImmutable(u);
        this.maxRoleNumber = u.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() { return this.g1.duplicate(); }

    public Element getG2() { return this.g2.duplicate(); }

    public Element getG3() { return this.g3.duplicate(); }

    public Element getGh() { return this.gh.duplicate(); }

    public Element getU0() { return this.u0.duplicate(); }

    public Element getUv() { return this.uv.duplicate(); }

    public Element[] getUs() { return this.u; }

    public Element getUsAt(int index) {
        return this.u[index].duplicate();
    }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RBACLLW15PublicKeyParameters) {
            RBACLLW15PublicKeyParameters that = (RBACLLW15PublicKeyParameters)anObject;
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
            //Compare gh
            if (!PairingUtils.isEqualElement(this.gh, that.getGh())) {
                return false;
            }
            //Compare u0
            if (!PairingUtils.isEqualElement(this.u0, that.getU0())) {
                return false;
            }
            //Compare uv
            if (!PairingUtils.isEqualElement(this.uv, that.getUv())) {
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