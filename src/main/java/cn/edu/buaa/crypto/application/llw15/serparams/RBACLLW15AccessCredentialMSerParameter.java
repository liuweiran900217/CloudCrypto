package cn.edu.buaa.crypto.application.llw15.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control medical staff access credential parameters.
 */
public class RBACLLW15AccessCredentialMSerParameter extends PairingKeySerParameter {
    private final String[] roles;
    private transient Element[] elementRoles;
    private final byte[][] byteArraysElementRoles;

    private final String time;
    private transient Element elementTime;
    private final byte[] byteArrayElementTime;

    private transient Element a0;
    private final byte[] byteArrayElementA0;

    private transient Element a1;
    private final byte[] byteArrayElementA1;

    private transient Element a2;
    private final byte[] byteArrayElementA2;

    private transient Element bv;
    private final byte[] byteArrayElementBv;

    private transient Element[] bs;
    private final byte[][] byteArraysElementBs;


    public RBACLLW15AccessCredentialMSerParameter(PairingParameters pairingParameters,
                                                  String[] roles, Element[] elementRoles,
                                                  String time, Element elementTime,
                                                  Element a0, Element a1, Element a2, Element bv, Element[] bs) {
        super(true, pairingParameters);

        this.a0 = a0.getImmutable();
        this.byteArrayElementA0 = this.a0.toBytes();

        this.a1 = a1.getImmutable();
        this.byteArrayElementA1 = this.a1.toBytes();

        this.a2 = a2.getImmutable();
        this.byteArrayElementA2 = this.a2.toBytes();

        this.bv = bv.getImmutable();
        this.byteArrayElementBv = this.bv.toBytes();

        this.bs = ElementUtils.cloneImmutable(bs);
        this.byteArraysElementBs = PairingUtils.GetElementArrayBytes(this.bs);

        this.roles = roles;
        this.elementRoles = ElementUtils.cloneImmutable(elementRoles);
        this.byteArraysElementRoles = PairingUtils.GetElementArrayBytes(this.elementRoles);

        this.time = time;
        this.elementTime = elementTime.getImmutable();
        this.byteArrayElementTime = this.elementTime.toBytes();
    }

    public String getRoleAt(int index) { return this.roles[index]; }

    public String[] getRoles() { return this.roles; }

    public String getTime() { return this.time; }

    public Element getElementRoleAt(int index) { return this.elementRoles[index].duplicate(); }

    public Element getElementTime() { return this.elementTime.duplicate(); }

    public Element[] getElementRoles() { return this.elementRoles; }

    public Element getA0() { return this.a0.duplicate(); }

    public Element getA1() { return this.a1.duplicate(); }

    public Element getA2() { return this.a2.duplicate(); }

    public Element getBv() { return this.bv.duplicate(); }

    public Element getBsAt(int index) { return this.bs[index].duplicate(); }

    public Element[] getBs() { return this.bs; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RBACLLW15AccessCredentialMSerParameter) {
            RBACLLW15AccessCredentialMSerParameter that = (RBACLLW15AccessCredentialMSerParameter)anOjbect;
            //Compare roles
            if (!Arrays.equals(this.roles, that.getRoles())) {
                return false;
            }
            //Compare elementRoles
            if (!PairingUtils.isEqualElementArray(this.elementRoles, that.getElementRoles())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysElementRoles, that.byteArraysElementRoles)) {
                return false;
            }
            //Compare a0
            if (!PairingUtils.isEqualElement(this.a0, that.getA0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementA0, that.byteArrayElementA0)) {
                return false;
            }
            //Compare a1
            if (!PairingUtils.isEqualElement(this.a1, that.getA1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementA1, that.byteArrayElementA1)) {
                return false;
            }
            //Compare a2
            if (!PairingUtils.isEqualElement(this.a2, that.getA2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementA2, that.byteArrayElementA2)) {
                return false;
            }
            //Compare bv
            if (!PairingUtils.isEqualElement(this.bv, that.getBv())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayElementBv, that.byteArrayElementBv)) {
                return false;
            }
            //Compare bs
            if (!PairingUtils.isEqualElementArray(this.bs, that.getBs())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysElementBs, that.byteArraysElementBs)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.elementRoles = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementRoles, PairingUtils.PairingGroupType.Zr);
        this.elementTime = pairing.getZr().newElementFromBytes(this.byteArrayElementTime);
        this.a0 = pairing.getG1().newElementFromBytes(this.byteArrayElementA0);
        this.a1 = pairing.getG1().newElementFromBytes(this.byteArrayElementA1);
        this.a2 = pairing.getG1().newElementFromBytes(this.byteArrayElementA2);
        this.bv= pairing.getG1().newElementFromBytes(this.byteArrayElementBv);
        this.bs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysElementBs, PairingUtils.PairingGroupType.G1);
    }
}

