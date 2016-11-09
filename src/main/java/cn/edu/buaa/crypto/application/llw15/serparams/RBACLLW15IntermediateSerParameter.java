package cn.edu.buaa.crypto.application.llw15.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate parameters.
 */
public class RBACLLW15IntermediateSerParameter extends PairingCipherSerParameter {
    private transient Element r;
    private final byte[] byteArrayR;

    private transient Element g_3_r;
    private final byte[] byteArrayG_3_r;

    private transient Element g_h_r;
    private final byte[] byteArrayG_h_r;

    private transient Element g_r;
    private final byte[] byteArrayG_r;

    private transient Element u_0_r;
    private final byte[] byteArrayU_0_r;

    private transient Element u_v_r;
    private final byte[] byteArrayU_v_r;

    private transient Element[] u_s_r;
    private final byte[][] byteArraysU_s_r;

    public RBACLLW15IntermediateSerParameter(PairingParameters pairingParameters,
                                             Element r, Element g_3_r, Element g_h_r,
                                             Element g_r, Element u_0_r, Element u_v_r, Element[] u_s_r) {
        super(pairingParameters);
        this.r = r.getImmutable();
        this.byteArrayR = this.r.toBytes();

        this.g_3_r = g_3_r.getImmutable();
        this.byteArrayG_3_r = this.g_3_r.toBytes();

        this.g_h_r = g_h_r.getImmutable();
        this.byteArrayG_h_r = this.g_h_r.toBytes();

        this.g_r = g_r.getImmutable();
        this.byteArrayG_r = this.g_r.toBytes();

        this.u_0_r = u_0_r.getImmutable();
        this.byteArrayU_0_r = this.u_0_r.toBytes();

        this.u_v_r = u_v_r.getImmutable();
        this.byteArrayU_v_r = this.u_v_r.toBytes();

        this.u_s_r = ElementUtils.cloneImmutable(u_s_r);
        this.byteArraysU_s_r = PairingUtils.GetElementArrayBytes(this.u_s_r);
    }

    public Element get_r() { return this.r.getImmutable(); }

    public Element get_G_3_r() { return this.g_3_r.duplicate(); }

    public Element get_G_h_r() { return this.g_h_r.duplicate(); }

    public Element get_G_r() { return this.g_r.duplicate(); }

    public Element get_U_0_r() { return this.u_0_r.duplicate(); }

    public Element get_U_v_r() { return this.u_v_r.duplicate(); }

    public Element get_U_s_r_at(int index) { return this.u_s_r[index]; }

    public Element[] get_U_s_r() { return this.u_s_r; }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof RBACLLW15IntermediateSerParameter) {
            RBACLLW15IntermediateSerParameter that = (RBACLLW15IntermediateSerParameter)anOjbect;
            //Compare r
            if (!PairingUtils.isEqualElement(this.r, that.get_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayR, that.byteArrayR)) {
                return false;
            }
            //Compare g_3_r
            if (!PairingUtils.isEqualElement(this.g_3_r, that.get_G_3_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG_3_r, that.byteArrayG_3_r)) {
                return false;
            }
            //Compare g_h_r
            if (!PairingUtils.isEqualElement(this.g_h_r, that.get_G_h_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG_h_r, that.byteArrayG_h_r)) {
                return false;
            }
            //Compare g_r
            if (!PairingUtils.isEqualElement(this.g_r, that.get_G_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG_r, that.byteArrayG_r)) {
                return false;
            }
            //Compare u_0_r
            if (!PairingUtils.isEqualElement(this.u_0_r, that.get_U_0_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU_0_r, that.byteArrayU_0_r)) {
                return false;
            }
            //Compare u_v_r
            if (!PairingUtils.isEqualElement(this.u_v_r, that.get_U_v_r())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU_v_r, that.byteArrayU_v_r)) {
                return false;
            }
            //Compare u_s_r
            if (!PairingUtils.isEqualElementArray(this.u_s_r, that.get_U_s_r())) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysU_s_r, that.byteArraysU_s_r)) {
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
        this.r = pairing.getZr().newElementFromBytes(this.byteArrayR);
        this.g_3_r = pairing.getG1().newElementFromBytes(this.byteArrayG_3_r);
        this.g_h_r = pairing.getG1().newElementFromBytes(this.byteArrayG_h_r);
        this.g_r = pairing.getG1().newElementFromBytes(this.byteArrayG_r);
        this.u_0_r = pairing.getG1().newElementFromBytes(this.byteArrayU_0_r);
        this.u_v_r = pairing.getG1().newElementFromBytes(this.byteArrayU_v_r);
        this.u_s_r = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysU_s_r, PairingUtils.PairingGroupType.G1);
    }
}
