package cn.edu.buaa.crypto.encryption.ibe.gen06a.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingDecapsulationGenerator;
import cn.edu.buaa.crypto.algebra.generators.PairingDecryptionGenerator;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aCiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aHeaderSerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.gen06a.serparams.IBEGen06aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.genparams.IBEDecryptionGenerationParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Gentry CPA-secure IBE decryption generator.
 */
public class IBEGen06aDecryptionGenerator implements PairingDecryptionGenerator, PairingDecapsulationGenerator {
    private IBEDecryptionGenerationParameter params;

    private Element sessionKey;

    public void init(CipherParameters params) {
        this.params = (IBEDecryptionGenerationParameter)params;
    }

    private void computeDecapsulation() throws InvalidCipherTextException {
        IBEGen06aPublicKeySerParameter publicKeyParameter = (IBEGen06aPublicKeySerParameter)this.params.getPublicKeyParameter();
        IBEGen06aSecretKeySerParameter secretKeyParameter = (IBEGen06aSecretKeySerParameter)this.params.getSecretKeyParameter();
        IBEGen06aHeaderSerParameter headerParameter = (IBEGen06aHeaderSerParameter) this.params.getCiphertextParameter();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element elementIdCT = PairingUtils.MapStringToGroup(pairing, this.params.getId(), PairingUtils.PairingGroupType.Zr);

        if (!secretKeyParameter.getElementId().equals(elementIdCT)){
            throw new InvalidCipherTextException("Secret Key identity vector does not match Ciphertext identity vector");
        }

        this.sessionKey = pairing.pairing(headerParameter.getU(), secretKeyParameter.getHId())
                .mul(headerParameter.getV().powZn(secretKeyParameter.getRId())).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }

    public Element recoverMessage() throws InvalidCipherTextException {
        computeDecapsulation();
        IBEGen06aCiphertextSerParameter ciphertextParameter = (IBEGen06aCiphertextSerParameter)this.params.getCiphertextParameter();
        return ciphertextParameter.getW().div(sessionKey).getImmutable();
    }
}