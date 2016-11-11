package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.params;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/9/19.
 *
 * Public Key parameters for Rouselakis-Waters CP-ABE.
 */
public class CPABERW13PublicKeySerParameter extends PairingKeySerParameter {
    private final AccessControlEngine accessControlEngine;
    private final Element g;
    private final Element u;
    private final Element h;
    private final Element w;
    private final Element v;
    private final Element eggAlpha;

    public CPABERW13PublicKeySerParameter(PairingParameters parameters, Element g, Element u, Element h,
                                          Element w, Element v, Element eggAlpha, AccessControlEngine accessControlEngine) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.u = u.getImmutable();
        this.h = h.getImmutable();
        this.w = w.getImmutable();
        this.v = v.getImmutable();
        this.eggAlpha = eggAlpha.getImmutable();
        this.accessControlEngine = accessControlEngine;
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getU() { return this.u.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getW() { return this.w.duplicate(); }

    public Element getV() { return this.v.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13PublicKeySerParameter) {
            CPABERW13PublicKeySerParameter that = (CPABERW13PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            //Compare w
            if (!PairingUtils.isEqualElement(this.w, that.getW())) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.getV())) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            //Compare access control engine
            if (!this.accessControlEngine.getEngineName().equals(that.getAccessControlEngine().getEngineName())) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
}
