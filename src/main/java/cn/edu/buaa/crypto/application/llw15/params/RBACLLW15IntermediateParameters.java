package cn.edu.buaa.crypto.application.llw15.params;

import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/10/8.
 *
 * Liu-Liu-Wu role-based access control intermediate parameters.
 */
public class RBACLLW15IntermediateParameters implements CipherParameters {
    private final Element r;
    private final Element g_3_r;
    private final Element g_h_r;
    private final Element g_r;
    private final Element u_0_r;
    private final Element u_v_r;
    private final Element[] u_s_r;

    public RBACLLW15IntermediateParameters(Element r, Element g_3_r, Element g_h_r,
                                           Element g_r, Element u_0_r, Element u_v_r, Element[] u_s_r) {
        this.r = r.getImmutable();
        this.g_3_r = g_3_r.getImmutable();
        this.g_h_r = g_h_r.getImmutable();
        this.g_r = g_r.getImmutable();
        this.u_0_r = u_0_r.getImmutable();
        this.u_v_r = u_v_r.getImmutable();
        this.u_s_r = ElementUtils.cloneImmutable(u_s_r);
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
        if (anOjbect instanceof RBACLLW15IntermediateParameters) {
            RBACLLW15IntermediateParameters that = (RBACLLW15IntermediateParameters)anOjbect;
            //Compare r
            if (!PairingUtils.isEqualElement(this.r, that.get_r())) {
                return false;
            }
            //Compare g_3_r
            if (!PairingUtils.isEqualElement(this.g_3_r, that.get_G_3_r())) {
                return false;
            }
            //Compare g_h_r
            if (!PairingUtils.isEqualElement(this.g_h_r, that.get_G_h_r())) {
                return false;
            }
            //Compare g_r
            if (!PairingUtils.isEqualElement(this.g_r, that.get_G_r())) {
                return false;
            }
            //Compare u_0_r
            if (!PairingUtils.isEqualElement(this.u_0_r, that.get_U_0_r())) {
                return false;
            }
            //Compare u_v_r
            if (!PairingUtils.isEqualElement(this.u_v_r, that.get_U_v_r())) {
                return false;
            }
            //Compare u_s_r
            if (!PairingUtils.isEqualElementArray(this.u_s_r, that.get_U_s_r())) {
                return false;
            }
            return true;
        }
        return false;
    }
}
