package cn.edu.buaa.crypto.encryption.hibbe.llw17.generators;

import cn.edu.buaa.crypto.algebra.generators.PairingEncapsulationPairGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.genparams.HIBBELLW17CiphertextGenerationParameter;
import cn.edu.buaa.crypto.encryption.hibbe.llw17.serparams.HIBBELLW17CipherSerParameter;
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
 * Liu-Liu-Wu composite-order CCA2-secure HIBBE session key / ciphertext pair generator.
 */
public class HIBBELLW17EncapsulationPairGenerator implements PairingEncapsulationPairGenerator {
    private HIBBELLW17CiphertextGenerationParameter params;

    public void init(CipherParameters params) {
        this.params = (HIBBELLW17CiphertextGenerationParameter)params;
    }

    public PairingKeyEncapsulationSerPair generateEncryptionPair() {
        Digest digest = this.params.getDigest();
        digest.reset();
        HIBBELLW17PublicKeySerParameter publicKeyParameters = this.params.getPublicKeyParameters();

        Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
        String[] ids = this.params.getIds();
        Element[] elementIds = PairingUtils.MapToZr(pairing, ids);

        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element sessionKey = publicKeyParameters.getEggAlpha().powZn(beta).getImmutable();
        byte[] byteArraySessionKey = sessionKey.toBytes();

        Element C0 = publicKeyParameters.getG().powZn(beta).getImmutable();
        Element C1 = publicKeyParameters.getH().getImmutable();
        for (int i = 0; i < publicKeyParameters.getMaxUser(); i++) {
            if (ids[i] != null) {
                C1 = C1.mul(publicKeyParameters.getUsAt(i).powZn(elementIds[i])).getImmutable();
            }
        }
        byte[] byteArrayC0 = C0.toBytes();
        digest.update(byteArrayC0, 0, byteArrayC0.length);
        byte[] byteArrayIDv = new byte[digest.getDigestSize()];
        digest.doFinal(byteArrayIDv, 0);
        Element elementIDv = PairingUtils.MapToZr(pairing, byteArrayIDv);
        C1 = C1.mul(publicKeyParameters.getUv().powZn(elementIDv)).powZn(beta).getImmutable();
        return new PairingKeyEncapsulationSerPair(
                byteArraySessionKey,
                new HIBBELLW17CipherSerParameter(publicKeyParameters.getParameters(), C0, C1));
    }
}