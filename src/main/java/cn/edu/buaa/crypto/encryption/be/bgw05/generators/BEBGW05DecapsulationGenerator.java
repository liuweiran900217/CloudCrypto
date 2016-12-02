package cn.edu.buaa.crypto.encryption.be.bgw05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05SecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEDecapsulationGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE session key decapsulation generator.
 */
public class BEBGW05DecapsulationGenerator implements PairingDecapsulationGenerator {
    private BEDecapsulationGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (BEDecapsulationGenerationParameter)params;
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        BEBGW05PublicKeySerParameter publicKeyParameters = (BEBGW05PublicKeySerParameter)this.params.getPublicKeyParameter();
        BEBGW05SecretKeySerParameter secretKeyParameters = (BEBGW05SecretKeySerParameter)this.params.getSecretKeyParameter();
        BEBGW05HeaderSerParameter ciphertextParameters = (BEBGW05HeaderSerParameter)this.params.getCiphertextParameter();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());

        int i = secretKeyParameters.getIndex();
        int[] indexSet = this.params.getIndexSet();
        boolean isInSet = false;
        //test if the user is in the broadcast receiver set
        for (int j : indexSet) {
            if (j > publicKeyParameters.getMaxUserNum() || j < 1) {
                throw new IllegalArgumentException("Illegal index in indexSet: " + j);
            }
            if (i == j) {
                isInSet = true;
                break;
            }
        }
        if (!isInSet) {
            throw new InvalidCipherTextException("index is not in the indexSet: " + i);
        }
        //decapsulation
        Element temp = secretKeyParameters.getD().getImmutable();
        for (int j : indexSet) {
            if (j == i) {
                continue;
            }
            temp = temp.mul(publicKeyParameters.getGsAt(publicKeyParameters.getMaxUserNum() + 1 - j + i)).getImmutable();
        }

        return pairing.pairing(publicKeyParameters.getGsAt(i), ciphertextParameters.getC1())
                .div(pairing.pairing(temp, ciphertextParameters.getC0())).toBytes();
    }
}
