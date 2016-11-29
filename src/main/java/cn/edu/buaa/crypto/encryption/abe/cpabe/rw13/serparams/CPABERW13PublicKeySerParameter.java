package cn.edu.buaa.crypto.encryption.abe.cpabe.rw13.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/11/29.
 *
 * Rouselakis-Waters CP-ABE public key parameter.
 */
public class CPABERW13PublicKeySerParameter extends PairingKeySerParameter {
    public transient Element g;
    private final byte[] byteArrayG;

    private transient Element u;
    private final byte[] byteArrayU;

    private transient Element h;
    private final byte[] byteArrayH;

    private transient Element w;
    private final byte[] byteArrayW;

    private transient Element v;
    private final byte[] byteArrayV;

    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;

    public CPABERW13PublicKeySerParameter(
            PairingParameters parameters, Element g, Element u, Element h, Element w, Element v, Element eggAlpha) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.u = u.getImmutable();
        this.byteArrayU = this.u.toBytes();

        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();

        this.w = w.getImmutable();
        this.byteArrayW = this.w.toBytes();

        this.v = w.getImmutable();
        this.byteArrayV = this.w.toBytes();


        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getU() { return this.u.duplicate(); }

    public Element getH() { return this.h.duplicate(); }

    public Element getW() { return this.w.duplicate(); }

    public Element getV() { return this.v.duplicate(); }

    public Element getEggAlpha() { return this.eggAlpha.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof CPABERW13PublicKeySerParameter) {
            CPABERW13PublicKeySerParameter that = (CPABERW13PublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare u
            if (!PairingUtils.isEqualElement(this.u, that.u)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayU, that.byteArrayU)) {
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.h)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                return false;
            }
            //Compare w
            if (!PairingUtils.isEqualElement(this.w, that.w)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayW, that.byteArrayW)) {
                return false;
            }
            //Compare v
            if (!PairingUtils.isEqualElement(this.v, that.v)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayV, that.byteArrayV)) {
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
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
        this.u = pairing.getG1().newElementFromBytes(this.byteArrayU).getImmutable();
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();
        this.w = pairing.getG1().newElementFromBytes(this.byteArrayW).getImmutable();
        this.v = pairing.getG1().newElementFromBytes(this.byteArrayV).getImmutable();
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();
    }
}
