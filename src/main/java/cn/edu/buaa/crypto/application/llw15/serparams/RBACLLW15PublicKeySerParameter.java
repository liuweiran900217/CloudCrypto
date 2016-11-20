package cn.edu.buaa.crypto.application.llw15.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/18.
 *
 * Liu-Liu-Wu role-based access control public key parameters.
 */
public class RBACLLW15PublicKeySerParameter extends PairingKeySerParameter {
    private final int maxRoleNumber;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element g1;
    private final byte[] byteArrayG1;

    private transient Element g2;
    private final byte[] byteArrayG2;

    private transient Element g3;
    private final byte[] byteArrayG3;

    private transient Element gh;
    private final byte[] byteArrayGh;

    //u0 is associated with the lifetime
    private transient Element u0;
    private final byte[] byteArrayU0;

    //uv is associated with the verification attribute
    private transient Element uv;
    private final byte[] byteArrayUv;

    private transient Element[] us;
    private final byte[][] byteArraysUs;

    public RBACLLW15PublicKeySerParameter(PairingParameters parameters, Element g, Element g1, Element g2, Element g3,
                                          Element gh, Element u0, Element uv, Element[] us) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.g1 = g1.getImmutable();
        this.byteArrayG1 = this.g1.toBytes();

        this.g2 = g2.getImmutable();
        this.byteArrayG2 = this.g2.toBytes();

        this.g3 = g3.getImmutable();
        this.byteArrayG3 = this.g3.toBytes();

        this.gh = gh.getImmutable();
        this.byteArrayGh = this.gh.toBytes();

        this.u0 = u0.getImmutable();
        this.byteArrayU0 = this.u0.toBytes();

        this.uv = uv.getImmutable();
        this.byteArrayUv = this.uv.toBytes();

        this.us = ElementUtils.cloneImmutable(us);
        this.byteArraysUs = PairingUtils.GetElementArrayBytes(this.us);

        this.maxRoleNumber = us.length;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getG1() { return this.g1.duplicate(); }

    public Element getG2() { return this.g2.duplicate(); }

    public Element getG3() { return this.g3.duplicate(); }

    public Element getGh() { return this.gh.duplicate(); }

    public Element getU0() { return this.u0.duplicate(); }

    public Element getUv() { return this.uv.duplicate(); }

    public Element[] getUs() { return this.us; }

    public Element getUsAt(int index) {
        return this.us[index].duplicate();
    }

    public int getMaxRoleNumber() { return this.maxRoleNumber; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RBACLLW15PublicKeySerParameter) {
            RBACLLW15PublicKeySerParameter that = (RBACLLW15PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare g1
            if (!PairingUtils.isEqualElement(this.g1, that.getG1())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG1, that.byteArrayG1)) {
                return false;
            }
            //Compare g2
            if (!PairingUtils.isEqualElement(this.g2, that.getG2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG2, that.byteArrayG2)) {
                return false;
            }
            //Compare g3
            if (!PairingUtils.isEqualElement(this.g3, that.getG3())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG3, that.byteArrayG3)) {
                return false;
            }
            //Compare gh
            if (!PairingUtils.isEqualElement(this.gh, that.getGh())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGh, that.byteArrayGh)) {
                return false;
            }
            //Compare u0
            if (!PairingUtils.isEqualElement(this.u0, that.getU0())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU0, that.byteArrayU0)) {
                return false;
            }
            //Compare uv
            if (!PairingUtils.isEqualElement(this.uv, that.getUv())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayUv, that.byteArrayUv)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElementArray(this.us, that.getUs())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysUs, that.byteArraysUs)) {
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
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.g1 = pairing.getG1().newElementFromBytes(this.byteArrayG1).getImmutable();
        this.g2 = pairing.getG1().newElementFromBytes(this.byteArrayG2).getImmutable();
        this.g3 = pairing.getG1().newElementFromBytes(this.byteArrayG3).getImmutable();
        this.gh = pairing.getG1().newElementFromBytes(this.byteArrayGh).getImmutable();
        this.u0 = pairing.getG1().newElementFromBytes(this.byteArrayU0).getImmutable();
        this.uv = pairing.getG1().newElementFromBytes(this.byteArrayUv).getImmutable();
        this.us = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysUs, PairingUtils.PairingGroupType.G1);
    }
}