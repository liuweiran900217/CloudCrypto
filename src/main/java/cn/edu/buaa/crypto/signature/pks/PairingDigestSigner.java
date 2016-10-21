package cn.edu.buaa.crypto.signature.pks;

import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

import java.io.IOException;

/**
 * Created by Weiran Liu on 2016/10/18.
 *
 * Pairing-based digital signature.
 */
public class PairingDigestSigner implements Signer {
    private final Digest digest;
    private final PairingSigner pairingSigner;
    private boolean forSigning;

    public PairingDigestSigner(PairingSigner signer, Digest digest)
    {
        this.digest = digest;
        this.pairingSigner = signer;
    }

    public void init(boolean forSigning, CipherParameters parameters)
    {
        this.forSigning = forSigning;
        AsymmetricKeyParameter k = (AsymmetricKeyParameter)parameters;
        if (forSigning && !k.isPrivate()) {
            throw new IllegalArgumentException("Signing Requires Private Key.");
        }

        if (!forSigning && k.isPrivate()) {
            throw new IllegalArgumentException("Verification Requires Public Key.");
        }

        reset();

        pairingSigner.init(forSigning, parameters);
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(byte input)
    {
        digest.update(input);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(byte[] input, int inOff, int length) {
        digest.update(input, inOff, length);
    }

    /**
     * Generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     */
    public byte[] generateSignature()
    {
        if (!forSigning)
        {
            throw new IllegalStateException("PairingDigestSigner not initialised for signature generation.");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        Element[] sig = pairingSigner.generateSignature(hash);

        try {
            return pairingSigner.derEncode(sig);
        } catch (IOException e) {
            throw new IllegalStateException("unable to encode signature");
        }
    }

    public boolean verifySignature(byte[] signature) {
        if (forSigning) {
            throw new IllegalStateException("PairingDigestSigner not initialised for verification");
        }

        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);

        try {
            Element[] sig = pairingSigner.derDecode(signature);
            return pairingSigner.verifySignature(hash, sig);
        } catch (IOException e) {
            return false;
        }
    }

    public void reset()
    {
        digest.reset();
    }

}