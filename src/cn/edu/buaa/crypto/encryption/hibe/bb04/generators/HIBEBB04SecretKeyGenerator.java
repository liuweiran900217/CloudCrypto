package cn.edu.buaa.crypto.encryption.hibe.bb04.generators;

import cn.edu.buaa.crypto.MapUtils;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04MasterSecretKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04PublicKeyParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04SecretKeyGenerationParameters;
import cn.edu.buaa.crypto.encryption.hibe.bb04.params.HIBEBB04SecretKeyParameters;
import it.unisa.dia.gas.crypto.cipher.CipherParametersGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * Created by Weiran Liu on 15-9-30.
 */
public class HIBEBB04SecretKeyGenerator implements CipherParametersGenerator {
    private KeyGenerationParameters params;

    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = keyGenerationParameters;
    }

    public CipherParameters generateKey() {
        if (params instanceof HIBEBB04SecretKeyGenerationParameters) {
            HIBEBB04SecretKeyGenerationParameters parameters = (HIBEBB04SecretKeyGenerationParameters)params;

            HIBEBB04MasterSecretKeyParameters masterSecretKeyParameters = parameters.getMasterSecretKeyParameters();
            HIBEBB04PublicKeyParameters publicKeyParameters = parameters.getPublicKeyParameters();
            assert(parameters.getLength() <= publicKeyParameters.getMaxLength());

            Pairing pairing = PairingFactory.getPairing(publicKeyParameters.getParameters());
            int length = parameters.getLength();

            Element[] elementIds = MapUtils.MapToZr(pairing, parameters.getIds());
            Element[] rs = new Element[length];
            Element[] ds = new Element[length];
            Element d0 = pairing.getG1().newOneElement();
            d0 = d0.mul(masterSecretKeyParameters.getG2Alpha());

            for (int i=0; i<rs.length; i++){
                rs[i] = pairing.getZr().newRandomElement().getImmutable();
                ds[i] = publicKeyParameters.getG().powZn(rs[i]).getImmutable();
                d0 = d0.mul(publicKeyParameters.getG1().powZn(elementIds[i]).mul(publicKeyParameters.getHAt(i)).powZn(rs[i]));
            }

            return new HIBEBB04SecretKeyParameters(publicKeyParameters.getParameters(), parameters.getIds(), elementIds, d0, ds);
        } else {
            //TODO Delegation
            return null;
        }
    }
}
