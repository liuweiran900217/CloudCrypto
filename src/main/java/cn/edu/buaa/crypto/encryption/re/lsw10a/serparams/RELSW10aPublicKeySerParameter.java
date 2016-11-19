package cn.edu.buaa.crypto.encryption.re.lsw10a.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/4/3.
 *
 * Lewko-Waters revocation encryption public key parameter.
 */
public class RELSW10aPublicKeySerParameter extends PairingKeySerParameter {
    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element gb;
    private final byte[] byteArrayGb;

    private transient Element gb2;
    private final byte[] byteArrayGb2;

    private transient Element hb;
    private final byte[] byteArrayHb;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public RELSW10aPublicKeySerParameter(PairingParameters parameters,
                                         Element g, Element g_b, Element g_b2, Element h_b, Element e_g_g_alpha) {
        super(false, parameters);
        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gb = g_b.getImmutable();
        this.byteArrayGb = this.gb.toBytes();

        this.gb2 = g_b2.getImmutable();
        this.byteArrayGb2 = this.gb2.toBytes();

        this.hb = h_b.getImmutable();
        this.byteArrayHb = this.hb.toBytes();

        this.eggAlpha = e_g_g_alpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getGb() { return this.gb.duplicate(); }

    public Element getGb2() { return this.gb2.duplicate(); }

    public Element getHb() { return this.hb.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof RELSW10aPublicKeySerParameter) {
            RELSW10aPublicKeySerParameter that = (RELSW10aPublicKeySerParameter) anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare g_b
            if (!PairingUtils.isEqualElement(this.gb, that.getGb())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGb, that.byteArrayGb)) {
                return false;
            }
            //Compare g_b2
            if (!PairingUtils.isEqualElement(this.gb2, that.getGb2())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGb2, that.byteArrayGb2)) {
                return false;
            }
            //Compare h_b
            if (!PairingUtils.isEqualElement(this.hb, that.getHb())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayHb, that.byteArrayHb)) {
                return false;
            }
            //Compare e_g_g_alpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.getEggAlpha())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
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
        this.gb = pairing.getG1().newElementFromBytes(this.byteArrayGb).getImmutable();
        this.gb2 = pairing.getG1().newElementFromBytes(this.byteArrayGb2).getImmutable();
        this.hb = pairing.getG1().newElementFromBytes(this.byteArrayHb).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}
