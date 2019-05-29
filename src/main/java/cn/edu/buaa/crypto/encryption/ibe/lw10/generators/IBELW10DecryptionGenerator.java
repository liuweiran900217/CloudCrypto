package cn.edu.buaa.crypto.encryption.ibe.lw10.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10HeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10PublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.lw10.serparams.IBELW10SecretKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
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
public class IBELW10DecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private IBEDecryptionGenerationParameter params;

    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (IBEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        IBELW10PublicKeySerParameter publicKeyParameter = (IBELW10PublicKeySerParameter)this.params.getPublicKeyParameter();
        IBELW10SecretKeySerParameter secretKeyParameter = (IBELW10SecretKeySerParameter)this.params.getSecretKeyParameter();
        IBELW10HeaderSerParameter headerParameter = (IBELW10HeaderSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        Element temp0 = pairing.pairing(secretKeyParameter.getK2(), headerParameter.getC2()).getImmutable();
        Element temp1 = pairing.pairing(secretKeyParameter.getK1(), headerParameter.getC1()).getImmutable();
        this.sessionKey = temp0.div(temp1).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        IBELW10CiphertextSerParameter ciphertextParameter = (IBELW10CiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getC0().div(sessionKey).getImmutable();
    }
}
