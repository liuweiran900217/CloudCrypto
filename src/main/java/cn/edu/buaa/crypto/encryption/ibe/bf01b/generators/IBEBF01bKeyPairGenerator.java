package cn.edu.buaa.crypto.encryption.ibe.bf01b.generators;

import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.generators.IBEBF01aKeyPairGenerator;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01a.serparams.IBEBF01aPublicKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bMasterSecretKeySerParameter;
import cn.edu.buaa.crypto.encryption.ibe.bf01b.serparams.IBEBF01bPublicKeySerParameter;

/**
 * Created by Weiran Liu on 2016/12/1.
 *
 * Boneh-Franklin CCA2-secure IBE public key / master secret key pair generator.
 */
public class IBEBF01bKeyPairGenerator extends IBEBF01aKeyPairGenerator {
    @Override
    public PairingKeySerPair generateKeyPair() {
        PairingKeySerPair pairingKeySerPair = super.generateKeyPair();
        IBEBF01aPublicKeySerParameter publicKeyParameter = (IBEBF01aPublicKeySerParameter) pairingKeySerPair.getPublic();
        IBEBF01aMasterSecretKeySerParameter masterSecretKeyParameter = (IBEBF01aMasterSecretKeySerParameter) pairingKeySerPair.getPrivate();

        return new PairingKeySerPair(
                new IBEBF01bPublicKeySerParameter(publicKeyParameter),
                new IBEBF01bMasterSecretKeySerParameter(masterSecretKeyParameter));
    }
}
