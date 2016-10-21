package cliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import sun.security.x509.*;
import java.security.cert.*;
import java.security.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
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
	
	
	public static void main(String[] args) throws IOException {
		new Cliente();
		
		
	}
	
	public Cliente()  throws IOException
	{
		
		System.out.println("Puerto");
		consola = new BufferedReader(new InputStreamReader(System.in));
		int puerto = consola.read();
		socket = new Socket();
		socket.connect(new InetSocketAddress("localhost", 4444));
		 out = new PrintWriter( socket.getOutputStream( ), true );
         in = new BufferedReader( new InputStreamReader( socket.getInputStream( ) ) );
         conectar();
	}
	
	public void conectar() throws IOException
	{
		
		out.println("HOLA");
		if(in.readLine().equals("OK"))
		{
			System.out.println("conectado, QUE ALGORITMOS DESEA.");
			out.println("ALGORITMOS:DES:RSA:HMACMD5");
		}
		
		
	}
	
	public X509Certificate crearCertificado()
	{
		Date startDate = new Date();                // time from which certificate is valid
		Date expiryDate = new Date( System.currentTimeMillis() + 86400000L);               // time after which certificate is not valid
		BigInteger serialNumber = new BigInteger(32,new Random());       // serial number for certificate
		PrivateKey caKey = ...;              // private key of the certifying authority (ca) certificate
		X509Certificate caCert = ...;        // public key certificate of the certifying authority
		KeyPair keyPair = ...;               // public/private key pair that we are creating certificate for
		X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
		X500Principal              subjectName = new X500Principal("CN=Test V3 Certificate");
		 
		certGen.setSerialNumber(serialNumber);
		certGen.setIssuerDN(caCert.getSubjectX500Principal());
		certGen.setNotBefore(startDate);
		certGen.setNotAfter(expiryDate);
		certGen.setSubjectDN(subjectName);
		certGen.setPublicKey(keyPair.getPublic());
		certGen.setSignatureAlgorithm(signatureAlgorithm);
		 
		certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
		                        new AuthorityKeyIdentifierStructure(caCert));
		certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
		                        new SubjectKeyIdentifierStructure(keyPair.getPublic());
		 
		X509Certificate cert = certGen.generate(caKey, "BC"); 
	}
	

}
