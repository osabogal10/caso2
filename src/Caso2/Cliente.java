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
import java.io.UnsupportedEncodingException;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.crypto.KeyGenerationParameters;
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
	private SecretKey llaveSim;
	
	public static void main(String[] args) throws IOException {
		new Cliente();
		
		
		
	}
	
	public Cliente()  throws IOException
	{
		
		System.out.println("Puerto");
		consola = new BufferedReader(new InputStreamReader(System.in));
//		int puerto = Integer.parseInt(consola.readLine());
		socket = new Socket();
		socket.connect(new InetSocketAddress("localhost", puerto));
		 out = new PrintWriter( socket.getOutputStream( ), true );
		 is = socket.getInputStream();
         in = new BufferedReader( new InputStreamReader( is ) );
         generarLlaves();
         
//         if(puerto == 4444)
//         {
//        	 conexion4444();
//         }
//         else if (puerto == 4443)
//         {
//        	 conexion4443();
//         }
//         else
//         {
//        	 System.out.println("PUERTO INVALIDO");
//         }
         
         
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
			algS = "AES";
			algA = "RSA";
			algD = "HMACSHA256";
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
					X509Certificate certServ = 	leerCertificado();
					byte[] arr = leerllave();
					
					llaveSim = descifrar(arr);
					byte[] cifrada = cifrarLlave(certServ.getPublicKey());
					String codificada = codificarHex(cifrada);
					out.println(codificada);
					consultar();
					String serv =in.readLine();
					leerResultado(serv);
				  }
				  catch (Exception e) {
					// TODO: handle exception
					  e.printStackTrace();
				}
			}
			else if(respuesta.equals("ERROR"))
			{
				System.out.println("ERROR EN EL SERVIDOR");
			}
		}	
	}
	
	public byte[] hmacDigest(byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
	InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}
	
	public static byte[] symmetricDecryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals("DES") || algo.equals("AES")?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public void leerResultado(String resp) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
	{
		String respuesta = codificarHex(symmetricDecryption(decodificarHex(resp), llaveSim, algS));
		System.out.println(respuesta);
	}
	
	public void consultar() throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException
	{
		if(in.readLine().equals("OK"))
		{
			String consulta = "201517263";
			
			byte[] digest = hmacDigest(consulta.getBytes(),llaveSim, algD);
			byte[] consultaCifrada = symmetricEncryption(consulta.getBytes(), llaveSim, algS);
			byte[] digestCifrado = symmetricEncryption(digest, llaveSim, algS);
			String resp = codificarHex(consultaCifrada)+":"+codificarHex(digestCifrado);
			System.out.println(resp);
			out.println(resp);
		}
	}
	
	public void imprimircert(X509Certificate certificado) throws Exception
	{
		
		PemWriter pWrt = new PemWriter(out);
		PemObject pemObj = new PemObject("CERTIFICATE",Collections.EMPTY_LIST, certificado.getEncoded());
		pWrt.writeObject(pemObj);
		pWrt.flush();
	}
	
	public X509Certificate leerCertificado()
	{
		X509Certificate cert = null;
		try {
			 cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
			System.out.println(cert.toString());
			out.println("OK");
			
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}
	
	public byte[] leerllave() throws IOException
	{
		String linea = in.readLine();
		linea = in.readLine();
		byte[] llaveSimServidor = decodificarHex(linea);
		return llaveSimServidor;
	}
	
	public byte[] decodificarHex(String ss)
	{
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
		return ret;
	}
	
	public SecretKey descifrar(byte [] cipheredText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		
		
		Cipher decifrador = Cipher.getInstance(algA);
		decifrador.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] llaveDecifrada = decifrador.doFinal(cipheredText);
		
		SecretKeySpec llaveRecibida = new SecretKeySpec(llaveDecifrada, algS);
		return llaveRecibida;
		
	}
	
	public static byte[] symmetricEncryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals("DES") || algo.equals("AES")?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}
	
	public byte[] cifrarLlave(Key key ) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		KeyGenerator keygen = KeyGenerator.getInstance(algS);
		keygen.init(128);
		SecretKey llave = keygen.generateKey();
		
		Cipher cifrador = Cipher.getInstance(algA);
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		byte [] encriptada = cifrador.doFinal(llave.getEncoded());
		
		return encriptada;

	}
	
	public String codificarHex (byte[] arr)
	{
		String ret = "";
		for (int i = 0 ; i < arr.length ; i++) {
			String g = Integer.toHexString(((char)arr[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
		return ret;
	}
	
}
