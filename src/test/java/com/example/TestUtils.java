package com.example;

import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * Created by Weiran Liu on 2015/10/5.
 *
 * Utilities used in Unit Test
 */
public class TestUtils {
    public static final int R_BIT_LENGTH = 160;
    public static final int Q_BIT_LENGTH = 512;

    public static final int NUM_OF_PRIME_FACTORS = 3;
    public static final int PRIME_BIT_LENGTH = 256;

    public static byte[] SerCipherParameter(CipherParameters cipherParameters) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(cipherParameters);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        objectOutputStream.close();
        byteArrayOutputStream.close();
        return byteArray;
    }

    public static CipherParameters deserCipherParameters(byte[] byteArrays) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrays);
        ObjectInputStream objectInputStream = new ObjectInputStream(byteArrayInputStream);
        CipherParameters cipherParameters = (CipherParameters)objectInputStream.readObject();
        objectInputStream.close();
        byteArrayInputStream.close();
        return cipherParameters;
    }

    public static void OutputXMLDocument(String name, Document document) {
        try {
            Transformer t = TransformerFactory.newInstance().newTransformer();
            t.setOutputProperty(OutputKeys.INDENT,"yes");
            t.setOutputProperty(OutputKeys.METHOD, "xml");
            t.transform(new DOMSource(document), new StreamResult(new FileOutputStream(new File(name))));
        } catch (TransformerConfigurationException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (TransformerException e) {
            e.printStackTrace();
        }
    }

    public static Document InputXMLDocument(String name) {
        try {
            DocumentBuilder documentBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            return documentBuilder.parse(new File(name));
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        } catch (SAXException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void OutputPairingParameters(PairingParameters pairingParameters, String path) {
        Out out = new Out(path);
        out.println(pairingParameters);
    }

    public static Pairing InputPairingParameters(String path) {
        Pairing pairing = PairingFactory.getPairing(path);
        return pairing;
    }
}
