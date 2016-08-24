package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.algebra.PairingUtils;
import cn.edu.buaa.crypto.pairingkem.params.PairingKeyParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 */
public class RBACLLW15AccessCredentialMParameters extends PairingKeyParameters {
    private final String[] roles;
    private final Element[] elementRoles;

    private final String time;
    private final Element elementTime;

    private final Element a0;
    private final Element a1;
    private final Element a2;
    private final Element bv;
    private final Element[] bs;


    public RBACLLW15AccessCredentialMParameters(PairingParameters pairingParameters,
                                                String[] roles, Element[] elementRoles,
                                                String time, Element elementTime,
                                         Element a0, Element a1, Element a2, Element bv, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.a1 = a1.getImmutable();
        this.a2 = a2.getImmutable();
        this.bv = bv.getImmutable();
        this.bs = ElementUtils.cloneImmutable(bs);
        this.roles = new String[roles.length];

        System.arraycopy(roles, 0, this.roles, 0, this.roles.length);
        this.elementRoles = ElementUtils.cloneImmutable(elementRoles);

        this.time = new String(time);
        this.elementTime = elementTime.getImmutable();
    }

    public String getRoleAt(int index) { return this.roles[index]; }

    public String[] getRoles() { return Arrays.copyOf(roles, roles.length); }

    public String getTime() { return this.time; }

    public Element getElementRoleAt(int index) { return this.elementRoles[index].duplicate(); }

    public Element getElementTime() { return this.elementTime.duplicate(); }

    public Element[] getElementRoles() { return Arrays.copyOf(elementRoles, elementRoles.length); }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getA2() { return this.a2.duplicate(); }

    public Element getBv() { return this.bv.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return Arrays.copyOf(bs, bs.length); }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RBACLLW15AccessCredentialMParameters) {
            RBACLLW15AccessCredentialMParameters that = (RBACLLW15AccessCredentialMParameters)anOjbect;
            //Compare roles
            if (!Arrays.equals(this.roles, that.getRoles())) {
                return false;
            }
            //Compare elementRoles
            if (!PairingUtils.isEqualElementArray(this.elementRoles, that.getElementRoles())) {
                return false;
            }
            //Compare a0
            if (!PairingUtils.isEqualElement(this.a0, that.getA0())) {
                return false;
            }
            //Compare a1
            if (!PairingUtils.isEqualElement(this.a1, that.getA1())) {
                return false;
            }
            //Compare a2
            if (!PairingUtils.isEqualElement(this.a2, that.getA2())) {
                return false;
            }
            //Compare bv
            if (!PairingUtils.isEqualElement(this.bv, that.getBv())) {
                return false;
            }
            //Compare bs
            if (!PairingUtils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}

