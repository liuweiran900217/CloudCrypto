package cn.edu.buaa.crypto.encryption.ibe.bf01b.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aSecretKeyGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bSecretKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE secret key generator.
 */
public class IBEBF01bSecretKeyGenerator extends IBEBF01aSecretKeyGenerator {
    @Override
    public PairingKeySerParameter generateKey() {
        IBEBF01aSecretKeySerParameter secretKeyParameter = (IBEBF01aSecretKeySerParameter) super.generateKey();
        return new IBEBF01bSecretKeySerParameter(secretKeyParameter);
    }
}
