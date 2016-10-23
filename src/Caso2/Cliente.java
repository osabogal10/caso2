package Caso2;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;

import sun.security.x509.*;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Date;
import java.util.Random;

import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.IOException;

public class Cliente {
	
	private final static String ip = "localhost";
	private Socket socket;
	private PrintWriter out;
	private BufferedReader in;
	private BufferedReader consola;
	
	
	
	private String algS;
	private String algA;
	private String algD;
	
	private InputStream is;
	
	private KeyPair keyPair;
	
	public static void main(String[] args) throws IOException {
		new Cliente();
		
		
		
	}
	
	public Cliente()  throws IOException
	{
		
		System.out.println("Puerto");
		consola = new BufferedReader(new InputStreamReader(System.in));
		int puerto = Integer.parseInt(consola.readLine());
		socket = new Socket();
		socket.connect(new InetSocketAddress("localhost", puerto));
		 out = new PrintWriter( socket.getOutputStream( ), true );
		 is = socket.getInputStream();
         in = new BufferedReader( new InputStreamReader( is ) );
         generarLlaves();
         
         if(puerto == 4444)
         {
        	 conexion4444();
         }
         else if (puerto == 4443)
         {
        	 conexion4443();
         }
         else
         {
        	 System.out.println("PUERTO INVALIDO");
         }
         
         
	}
	
	private void generarLlaves() {
		KeyPairGenerator gen;
		try {
			gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(1024);
			 keyPair = gen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			System.out.println("fallo al generar las llaves");
			e.printStackTrace();
		}
		
		
	}

	public void conexion4444() throws IOException
	{
		
		out.println("HOLA");
		String respuesta = in.readLine();
		if(respuesta.equals("OK"))
		{
			out.println("ALGORITMOS:AES:RSA:HMACSHA256");
//			System.out.println("Insete algoritmo simetrico.");
//			algS = consola.readLine();
//			System.out.println("Insete algoritmo asimetrico.");
//			algA = consola.readLine();
//			System.out.println("Insete algoritmo de HMAC.");
//			algD = consola.readLine();
//			out.println("ALGORITMOS:"+algS+":"+algA +":"+algD);
			
			if(in.readLine().equals("OK"))
			{
				out.println("CERTFICADOCLIENTE");
				System.out.println("respuesta: "+in.readLine());
				out.println("OK");
				System.out.println("respuesta: "+in.readLine());
				out.println("CIFRADOKS+");
				System.out.println("respuesta: "+in.readLine());
				out.println("CIFRADOLS1");
				System.out.println("respuesta: "+in.readLine());
			}
			else if(respuesta.equals("ERROR"))
			{
				System.out.println("ERROR EN EL SERVIDOR");
			}
		}	
	}
	
	public void conexion4443() throws IOException
	{
		
		out.println("HOLA");
		String respuesta = in.readLine();
		if(respuesta.equals("OK"))
		{
			out.println("ALGORITMOS:AES:RSA:HMACSHA256");
//			System.out.println("Insete algoritmo simetrico.");
//			algS = consola.readLine();
//			System.out.println("Insete algoritmo asimetrico.");
//			algA = consola.readLine();
//			System.out.println("Insete algoritmo de HMAC.");
//			algD = consola.readLine();
//			out.println("ALGORITMOS:"+algS+":"+algA +":"+algD);
			
			if(in.readLine().equals("OK"))
			{
				
				  try {
					X509Certificate cert = Certificado.generateV3Certificate(keyPair);
					imprimircert(cert);
					leerCertificado();
				  }
				  catch (Exception e) {
					// TODO: handle exception
				}
			}
			else if(respuesta.equals("ERROR"))
			{
				System.out.println("ERROR EN EL SERVIDOR");
			}
		}	
	}
	
	public void imprimircert(X509Certificate certificado) throws Exception
	{
		
		PemWriter pWrt = new PemWriter(out);
		PemObject pemObj = new PemObject("CERTIFICATE",Collections.EMPTY_LIST, certificado.getEncoded());
		pWrt.writeObject(pemObj);
		pWrt.flush();
	}
	
	public void leerCertificado()
	{
		
		try {
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
			out.println("OK");
			
			System.out.println(cert.toString());
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
//	public void imprimircert(X509Certificate certificado)
//	{
//		String s = certificado.toString();
//		String[] array = s.split("\n");
//		for (int i = 0; i < array.length; i++) {
//			String temp = array[i];
//			temp.replace("\n", "");
//			out.println(temp);
//		}
//	}
	
	
//	@SuppressWarnings("deprecation")
//	public X509Certificate crearCertificado()
//	{
//		Date startDate = new Date();                // time from which certificate is valid
//		Date expiryDate = new Date( System.currentTimeMillis() + 86400000L);               // time after which certificate is not valid
//		BigInteger serialNumber = new BigInteger(32,new Random());       // serial number for certificate
//		           // private key of the certifying authority (ca) certificate
//		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
//		X500Principal subjectName = new X500Principal("CN=Test V3 Certificate");
//		 
//		certGen.setSerialNumber(serialNumber);
//		//certGen.setIssuerDN(caCert.getSubjectX500Principal());
//		certGen.setNotBefore(startDate);
//		certGen.setNotAfter(expiryDate);
//		certGen.setSubjectDN(subjectName);
//		certGen.setPublicKey(kPublica);
//		certGen.setSignatureAlgorithm("RSA");
//		X509Certificate cert = null;
//		try {
//			cert = certGen.generate(kPrivada, "BC");
//		} catch (CertificateEncodingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (InvalidKeyException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (IllegalStateException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoSuchProviderException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (NoSuchAlgorithmException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (SignatureException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return cert; 
//	}
	

}
