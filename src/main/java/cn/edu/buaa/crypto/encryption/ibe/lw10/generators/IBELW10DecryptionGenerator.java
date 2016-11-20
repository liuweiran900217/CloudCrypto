package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.utils.PairingUtils;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10CipherSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.genparams.IBELW10DecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/5/7.
 *
 * Lewko-Waters IBE decryption generator.
 */
public class IBELW10DecryptionGenerator implements PairingDecryptionGenerator {
    private IBELW10DecryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (IBELW10DecryptionGenerationParameter)params;
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        IBELW10PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();
        IBELW10SecretKeySerParameter secretKeyParameters = this.params.getSecretKeyParameters();
        IBELW10CipherSerParameter ciphertextParameters = this.params.getCiphertextParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        if (!secretKeyParameters.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        Element temp0 = pairing.pairing(secretKeyParameters.getK2(), ciphertextParameters.getC2()).getImmutable();
        Element temp1 = pairing.pairing(secretKeyParameters.getK1(), ciphertextParameters.getC1()).getImmutable();
        Element sessionKey = temp0.div(temp1).getImmutable();

        return ciphertextParameters.getC0().div(sessionKey).getImmutable();
    }
}
