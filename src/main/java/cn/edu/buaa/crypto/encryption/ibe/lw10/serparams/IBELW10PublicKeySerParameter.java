package cn.edu.buaa.crypto.encryption.ibe.lw10.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 16/5/6.
 *
 * Lewko-Waters IBE public key parameter.
 */
public class IBELW10PublicKeySerParameter extends PairingKeySerParameter {

    private transient Element u;
    private final byte[] byteArrayU;

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public IBELW10PublicKeySerParameter(PairingParameters parameters, Element u, Element g, Element h, Element eggAlpha) {
        super(false, parameters);

        this.u = u.getImmutable();
        this.byteArrayU = this.u.toBytes();

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();

        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }

    public Element getU() { return this.u.duplicate(); }

    public Element getG() { return this.g.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBELW10PublicKeySerParameter) {
            IBELW10PublicKeySerParameter that = (IBELW10PublicKeySerParameter)anObject;
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.getU())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
                return false;
            }
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.getG())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.getH())) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare eggAlpha
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
        this.u = pairing.getG1().newElementFromBytes(this.byteArrayU).getImmutable();
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}
