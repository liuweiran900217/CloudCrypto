package cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CPA-secure IBE public key parameter.
 */
public class IBEBF01aPublicKeySerParameter extends PairingKeySerParameter {

    private transient Element g;
    private final byte[] byteArrayG;

    private transient Element gs;
    private final byte[] byteArrayGs;

    public IBEBF01aPublicKeySerParameter(PairingParameters parameters, Element g, Element gs) {
        super(false, parameters);

        this.g = g.getImmutable();
        this.byteArrayG = this.g.toBytes();

        this.gs = gs.getImmutable();
        this.byteArrayGs = this.gs.toBytes();
    }

    public Element getG() { return this.g.duplicate(); }

    public Element getGs() { return this.gs.duplicate(); }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof IBEBF01aPublicKeySerParameter) {
            IBEBF01aPublicKeySerParameter that = (IBEBF01aPublicKeySerParameter)anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                return false;
            }
            //Compare gs
            if (!PairingUtils.isEqualElement(this.gs, that.gs)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGs, that.byteArrayGs)) {
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
        this.gs = pairing.getG1().newElementFromBytes(this.byteArrayGs).getImmutable();
    }
}
