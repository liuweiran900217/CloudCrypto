package cn.edu.buaa.crypto.algebra.serparams;

import it.unisa.dia.gas.jpbc.PairingParameters;

/**
 * Created by Weiran Liu on 2016/11/9.
 *
 * Serializable asymmetric key parameter.
 * This is the same as AsymmetricKeyParameters, except that this is serializable.
 * All the asymmetric key parameters should extend this class for supporting serialization.
 */
public class PairingKeySerParameter extends PairingCipherSerParameter {
    private boolean privateKey;

    public PairingKeySerParameter(boolean privateKey, PairingParameters pairingParameters) {
        super(pairingParameters);
        this.privateKey = privateKey;
    }

    public boolean isPrivate()
    {
        return privateKey;
    }

    @Override
    public boolean equals(Object anOjbect) {
        if (this == anOjbect) {
            return true;
        }
        if (anOjbect instanceof PairingKeySerParameter) {
            PairingKeySerParameter that = (PairingKeySerParameter)anOjbect;
            //Compare Pairing Parameters
            return (this.privateKey == that.privateKey);
        }
        return false;
    }
}
