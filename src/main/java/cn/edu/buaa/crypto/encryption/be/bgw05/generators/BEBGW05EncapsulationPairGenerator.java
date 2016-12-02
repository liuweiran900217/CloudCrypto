package cn.edu.buaa.crypto.encryption.be.bgw05.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.be.bgw05.serparams.BEBGW05PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.be.genparams.BEEncapsulationGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/12/2.
 *
 * Boneh-Gentry-Waters BE session key encapsulation generator.
 */
public class BEBGW05EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {

    private BEEncapsulationGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (BEEncapsulationGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        BEBGW05PublicKeySerParameter publicKeyParameters = (BEBGW05PublicKeySerParameter)this.params.getPublicKeyParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        int[] indexSet = this.params.getIndexSet();
        Element t = pairing.getZr().newRandomElement().getImmutable();
        //Computer session key
        Element sessionKey = pairing.pairing(publicKeyParameters.getGsAt(1), publicKeyParameters.getGsAt(publicKeyParameters.getMaxUserNum())).powZn(t).getImmutable();

        //Computer C0
        Element C0 = publicKeyParameters.getG().powZn(t).getImmutable();

        //Compute C1
        Element C1 = publicKeyParameters.getV().getImmutable();
        for (int j : indexSet) {
            if (j > publicKeyParameters.getMaxUserNum() || j < 1) {
                throw new IllegalArgumentException("Illegal index in the indexSet: " + j);
            }
            C1 = C1.mul(publicKeyParameters.getGsAt(publicKeyParameters.getMaxUserNum() + 1 - j)).getImmutable();
        }
        C1 = C1.powZn(t).getImmutable();
        return new PairingKeyEncapsulationSerPair(
                sessionKey.toBytes(),
                new BEBGW05HeaderSerParameter(publicKeyParameters.getParameters(), C0, C1));
    }
}
