package cn.edu.buaa.crypto.encryption.hibbe.llw17.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncryptionGenerator;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.genparams.HIBBEEncryptionGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17CiphertextSerParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17PublicKeySerParameter;
import cn.edu.buaa.crypto.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;

/**
 * Created by Weiran Liu on 2016/11/11.
 *
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE encryption generator.
 */
public class HIBBELLW17EncryptionGenerator implements PairingEncryptionGenerator {
    private HIBBEEncryptionGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBEEncryptionGenerationParameter)params;
    }

    public PairingCipherSerParameter generateCiphertext() {
        Digest digest = this.params.getDigest();
        digest.reset();
        HIBBELLW17PublicKeySerParameter publicKeyParameters = (HIBBELLW17PublicKeySerParameter)this.params.getPublicKeyParameter();
        if (this.params.getIds().length != publicKeyParameters.getMaxUser()) {
            throw new IllegalArgumentException("Invalid identity vector set length");
        }

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapStringArrayToGroup(pairing, ids, PairingUtils.PairingGroupType.Zr);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(beta).getImmutable();
        Element C2 = sessionKey.mul(this.params.getMessage()).getImmutable();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element C1 = publicKeyParameters.getH().getImmutable();
        for (int i = 0; i < publicKeyParameters.getMaxUser(); i++) {
            if (ids[i] != null) {
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        byte[] byteArrayC0 = C0.toBytes();
        digest.update(byteArrayC0, 0, byteArrayC0.length);
        byte[] byteArrayC2 = C2.toBytes();
        digest.update(byteArrayC2, 0, byteArrayC2.length);
        byte[] byteArrayIDv = new byte[digest.getDigestSize()];
        digest.doFinal(byteArrayIDv, 0);


        Element elementIDv = PairingUtils.MapByteArrayToGroup(pairing, byteArrayIDv, PairingUtils.PairingGroupType.Zr);
        C1 = C1.mul(publicKeyParameters.getUv().powZn(elementIDv)).powZn(beta).getImmutable();
        return new HIBBELLW17CiphertextSerParameter(publicKeyParameters.getParameters(), C0, C1, C2);
    }
}