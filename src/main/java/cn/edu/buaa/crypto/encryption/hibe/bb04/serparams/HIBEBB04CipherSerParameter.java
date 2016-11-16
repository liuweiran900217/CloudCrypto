package cn.edu.buaa.crypto.encryption.hibe.bb04.serparams;

import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;

import java.util.Arrays;

/**
 * Created by Weiran Liu on 15-9-30.
 *
 * Ciphertext Parameters for Boneh-Boyen HIBE scheme.
 */
public class HIBEBB04CipherSerParameter extends PairingCipherSerParameter {
    private final int length;

    private transient Element B;
    private final byte[] byteArrayB;

    private transient Element[] Cs;
    private final byte[][] byteArraysCs;

    public HIBEBB04CipherSerParameter(PairingParameters pairingParameters, int length, Element B, Element[] Cs) {
        super(pairingParameters);
        this.length = length;

        this.B = B.getImmutable();
        this.byteArrayB = this.B.toBytes();

        this.Cs = ElementUtils.cloneImmutable(Cs);
        this.byteArraysCs = PairingUtils.GetElementArrayBytes(this.Cs);
    }

    public int getLength() { return this.length; }

    public Element getB() { return this.B.duplicate(); }

    public Element getCsAt(int index) { return this.Cs[index].duplicate(); }

    public Element[] getCs() { return this.Cs; }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof HIBEBB04CipherSerParameter) {
            HIBEBB04CipherSerParameter that = (HIBEBB04CipherSerParameter)anObject;
            //Compare length
            if (this.length != that.getLength()) {
                return false;
            }
            //Compare B
            if (!PairingUtils.isEqualElement(this.B, that.getB())){
                return false;
            }
            if (!Arrays.equals(this.byteArrayB, that.byteArrayB)) {
                return false;
            }
            //Compare Cs
            if (!PairingUtils.isEqualElementArray(this.Cs, that.getCs())){
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysCs, that.byteArraysCs)) {
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
        this.B = pairing.getG1().newElementFromBytes(this.byteArrayB);
        this.Cs = PairingUtils.GetElementArrayFromBytes(pairing, this.byteArraysCs, PairingUtils.PairingGroupType.G1);
    }
}
