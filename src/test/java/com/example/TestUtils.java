package com.example;

import cn.edu.buaa.crypto.algebra.generators.PairingParametersGenerator;
import cn.edu.buaa.crypto.algebra.genparams.PairingParametersGenerationParameter;
import edu.princeton.cs.algs4.Out;
import it.unisa.dia.gas.jpbc.PairingParameters;
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
    public static final String TEST_PAIRING_PARAMETERS_PATH_a_80_256 = "params/a_80_256.properties";
    public static final String TEST_PAIRING_PARAMETERS_PATH_a1_2_128 = "params/a1_2_128.properties";
    public static final String TEST_PAIRING_PARAMETERS_PATH_a1_3_128 = "params/a1_3_128.properties";

    public static final int DEFAULT_SIMU_TEST_ROUND = 2;
    public static final int DEFAULT_PRIME_ORDER_TEST_ROUND = 100;
    public static final int DEFAULT_COMPOSITE_ORDER_TEST_ROUND = 50;

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

    public static void main(String[] args) {
        PairingParametersGenerationParameter pairingParametersGenerationParameter =
                new PairingParametersGenerationParameter(3, 128);
        PairingParametersGenerator pairingParametersGenerator = new PairingParametersGenerator();
        pairingParametersGenerator.init(pairingParametersGenerationParameter);
        PairingParameters pairingParameters = pairingParametersGenerator.generateParameters();
        Out out = new Out("params/a1_3_128.properties");
        out.println(pairingParameters);
    }
}
