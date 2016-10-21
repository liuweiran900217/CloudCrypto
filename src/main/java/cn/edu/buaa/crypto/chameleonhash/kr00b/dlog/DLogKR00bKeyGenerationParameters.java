package cn.edu.buaa.crypto.chameleonhash.kr00b.dlog;

import cn.edu.buaa.crypto.algebra.params.SecurePrimeParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * Created by Weiran Liu on 2016/10/20.
 *
 * Krawczyk-Rabin Chameleon hash public key / secret key generation parameters.
 */
public class DLogKR00bKeyGenerationParameters extends KeyGenerationParameters
{
    private SecurePrimeParameters params;

    public DLogKR00bKeyGenerationParameters(SecureRandom random, SecurePrimeParameters params)
    {
        super(random, params.getP().bitLength() - 1);

        this.params = params;
    }

    public SecurePrimeParameters getParameters()
    {
        return params;
    }
}