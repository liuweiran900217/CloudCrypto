package cn.edu.buaa.crypto.encryption.ibbe;

import cn.edu.buaa.crypto.algebra.Engine;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeyEncapsulationSerPair;
import cn.edu.buaa.crypto.algebra.serparams.PairingKeySerParameter;
import cn.edu.buaa.crypto.algebra.serparams.PairingCipherSerParameter;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

/**
 * Created by Weiran Liu on 16/8/23.
 *
 * Identity-Based Broadcast Encryption Engine.
 * All instances should implement this Interface.
 */
public interface IBBEEngine extends Engine {
    /**
     * Setup Algorithm for IBBE
     * @param pairingParameters Pairing Parameters.
     * @param maxBroadcastReceiver maximal broadcast receivers, ignore if the scheme is unbounded
     * @return public key / master secret key pair of the scheme
     */
    PairingKeySerPair setup(PairingParameters pairingParameters, int maxBroadcastReceiver);

    /**
     * Secret Key Generation Algorithm for IBBE
     * @param publicKey public key
     * @param masterKey master secret key
     * @param id associated identity
     * @return secret key associated with the identity id
     */
    PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String id);

    /**
     * Key Encapsulation Algorithm for IBBE
     * @param publicKey public key
     * @param ids a broadcast identity set
     * @return session key / ciphertext pair associated with the broadcast identity set ids
     */
    PairingKeyEncapsulationSerPair encapsulation(PairingKeySerParameter publicKey, String[] ids);

    /**
     * Key Decapsulation Algorithm for IBBE
     * @param publicKey public key
     * @param secretKey secret key associated with an identity
     * @param ids broadcast identity set associating with the ciphertext
     * @param ciphertext ciphertext
     * @return the decapsulated session key
     * @throws InvalidCipherTextException if the decapsulation procedure is failure
     */
    byte[] decapsulation (PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                          String[] ids, PairingCipherSerParameter ciphertext
        ) throws InvalidCipherTextException;
    }
