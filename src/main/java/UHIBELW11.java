 import it.unisa.dia.gas.crypto.jpbc.fe.ibe.lw11.engines.UHIBELW11KEMEngine;
 import it.unisa.dia.gas.crypto.jpbc.fe.ibe.lw11.generators.UHIBELW11KeyPairGenerator;
 import it.unisa.dia.gas.crypto.jpbc.fe.ibe.lw11.generators.UHIBELW11SecretKeyGenerator;
 import it.unisa.dia.gas.crypto.jpbc.fe.ibe.lw11.params.*;
 import it.unisa.dia.gas.crypto.kem.KeyEncapsulationMechanism;
 import it.unisa.dia.gas.jpbc.Element;
 import it.unisa.dia.gas.jpbc.Pairing;
 import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
 import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
 import org.bouncycastle.crypto.CipherParameters;
 import org.bouncycastle.crypto.InvalidCipherTextException;

 import java.util.Arrays;

           import static org.junit.Assert.*;

           /**
     * @author Angelo De Caro (jpbclib@gmail.com)
     */
           public class UHIBELW11 {


                   public UHIBELW11() {
               }


                   public AsymmetricCipherKeyPair setup(int bitLength) {
                  UHIBELW11KeyPairGenerator setup = new UHIBELW11KeyPairGenerator();
                   setup.init(new UHIBELW11KeyPairGenerationParameters(bitLength));

                   return setup.generateKeyPair();
               }

                   public Element[] map(CipherParameters publicKey, String... ids) {
                   Pairing pairing = PairingFactory.getPairing(((UHIBELW11PublicKeyParameters) publicKey).getParameters());

                   Element[] elements = new Element[ids.length];
                   for (int i = 0; i < elements.length; i++) {
                           byte[] id = ids[i].getBytes();
                           elements[i] = pairing.getZr().newElementFromHash(id, 0, id.length);
                       }
                   return elements;
               }


                   public CipherParameters keyGen(AsymmetricCipherKeyPair masterKey, Element... ids) {
                   UHIBELW11SecretKeyGenerator generator = new UHIBELW11SecretKeyGenerator();
                   generator.init(new UHIBELW11SecretKeyGenerationParameters(
                                  (UHIBELW11MasterSecretKeyParameters) masterKey.getPrivate(),
                                   (UHIBELW11PublicKeyParameters) masterKey.getPublic(),
                                   ids
                   ));

                   return generator.generateKey();
               }

                   public CipherParameters delegate(AsymmetricCipherKeyPair masterKey, CipherParameters secretKey, Element id) {
                   UHIBELW11SecretKeyGenerator generator = new UHIBELW11SecretKeyGenerator();
                   generator.init(new UHIBELW11DelegateGenerationParameters(
                                  (UHIBELW11PublicKeyParameters) masterKey.getPublic(),
                                   (UHIBELW11SecretKeyParameters) secretKey,
                                   id
                   ));

                   return generator.generateKey();
               }

                   public byte[][] encaps(CipherParameters publicKey, Element... ids) {
                   try {
                           KeyEncapsulationMechanism kem = new UHIBELW11KEMEngine();
                           kem.init(true, new UHIBELW11EncryptionParameters((UHIBELW11PublicKeyParameters) publicKey, ids));

                           byte[] ciphertext = kem.process();

                           assertNotNull(ciphertext);
                           assertNotSame(0, ciphertext.length);

                           byte[] key = Arrays.copyOfRange(ciphertext, 0, kem.getKeyBlockSize());
                           byte[] ct = Arrays.copyOfRange(ciphertext, kem.getKeyBlockSize(), ciphertext.length);

                           return new byte[][]{key, ct};
                       } catch (InvalidCipherTextException e) {
                           e.printStackTrace();
                           fail(e.getMessage());
                       }
                   return null;
               }

                  public byte[] decaps(CipherParameters secretKey, byte[] cipherText) {
                   try {
                           KeyEncapsulationMechanism kem = new UHIBELW11KEMEngine();

                           kem.init(false, secretKey);
                           byte[] key = kem.processBlock(cipherText);

                           assertNotNull(key);
                           assertNotSame(0, key.length);

                          return key;
                      } catch (InvalidCipherTextException e) {
                          e.printStackTrace();
                          fail(e.getMessage());
                      }

                  return null;
              }

                  public static void main(String[] args) {
                  UHIBELW11 engine = new UHIBELW11();

                 // Setup
                  AsymmetricCipherKeyPair keyPair = engine.setup(32);

                  // KeyGen
                  Element[] ids = engine.map(keyPair.getPublic(), "angelo", "de caro", "unisa");

                  CipherParameters sk0 = engine.keyGen(keyPair, ids[0]);
                  CipherParameters sk01 = engine.keyGen(keyPair, ids[0], ids[1]);
                  CipherParameters sk012 = engine.keyGen(keyPair, ids[0], ids[1], ids[2]);

                  CipherParameters sk1 = engine.keyGen(keyPair, ids[1]);
                  CipherParameters sk10 = engine.keyGen(keyPair, ids[1], ids[0]);
                  CipherParameters sk021 = engine.keyGen(keyPair, ids[0], ids[2], ids[1]);

                  // Encryption/Decryption
                  byte[][] ciphertext0 = engine.encaps(keyPair.getPublic(), ids[0]);
                  byte[][] ciphertext01 = engine.encaps(keyPair.getPublic(), ids[0], ids[1]);
                  byte[][] ciphertext012 = engine.encaps(keyPair.getPublic(), ids[0], ids[1], ids[2]);

                  // Decrypt
                  assertEquals(true, Arrays.equals(ciphertext0[0], engine.decaps(sk0, ciphertext0[1])));
                  assertEquals(true, Arrays.equals(ciphertext01[0], engine.decaps(sk01, ciphertext01[1])));
                  assertEquals(true, Arrays.equals(ciphertext012[0], engine.decaps(sk012, ciphertext012[1])));

                  assertEquals(false, Arrays.equals(ciphertext0[0], engine.decaps(sk1, ciphertext0[1])));
                  assertEquals(false, Arrays.equals(ciphertext01[0], engine.decaps(sk10, ciphertext01[1])));
                  assertEquals(false, Arrays.equals(ciphertext012[0], engine.decaps(sk021, ciphertext012[1])));

                  // Delegate/Decrypt
                  assertEquals(true, Arrays.equals(ciphertext01[0], engine.decaps(engine.delegate(keyPair, sk0, ids[1]), ciphertext01[1])));
                  assertEquals(true, Arrays.equals(ciphertext012[0], engine.decaps(engine.delegate(keyPair, sk01, ids[2]), ciphertext012[1])));
                  assertEquals(true, Arrays.equals(ciphertext012[0], engine.decaps(engine.delegate(keyPair, engine.delegate(keyPair, sk0, ids[1]), ids[2]), ciphertext012[1])));

                  assertEquals(false, Arrays.equals(ciphertext01[0], engine.decaps(engine.delegate(keyPair, sk0, ids[0]), ciphertext01[1])));
                  assertEquals(false, Arrays.equals(ciphertext012[0], engine.decaps(engine.delegate(keyPair, sk01, ids[1]), ciphertext012[1])));
                  assertEquals(false, Arrays.equals(ciphertext012[0], engine.decaps(engine.delegate(keyPair, engine.delegate(keyPair, sk0, ids[2]), ids[1]), ciphertext012[1])));
              }

              }