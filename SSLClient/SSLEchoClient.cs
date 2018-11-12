/*
 * TCPEchoClient1
 *
 * Author Michael Claudius, ZIBAT Computer Science
 * Version 1.0. 2014.02.12, 1.1 2015.10.09
 * Copyright 2014 by Michael Claudius
 * Revised 2015.11.10
 * All rights reserved
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SSLClient
{
    class SSLEchoClient
    {
        static void Main(string[] args)
        {
            try
            {
                //Client certificate 
                string clientCertificateFile = "c:/certificates/RootCA.cer";
                // x509 certificate  
                X509Certificate clientCertificate = new X509Certificate(clientCertificateFile, "secret1");

                // define TLS (transport layer security) protocol 
                SslProtocols enabledSSLProtocols = SslProtocols.Tls;  //Superseeds the former SslProtocols.Ssl3

                
                //Alternative for validation of client
                // or collection of X509 certificates
                X509CertificateCollection certificateCollection = new X509CertificateCollection {clientCertificate};
                // Server certificate name "FakeServerName" mentioned inside the ServerSSL certificate 
                // ServerSSL cer issue to "FakeServerName"
                string serverName = "FakeServerName";

                TcpClient clientSocket = new TcpClient("localhost", 6789);
                Stream unsecuredStream = clientSocket.GetStream();
                //No revocation
                //SslStream sslStream = new SslStream(unsecureStream, leaveInnerStreamOpen, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                //Setup for handling the validation of server  
                // Verify the remote secure socket layer (SSL) certificate used for authentication
                var userCertificateValidationCallback = new RemoteCertificateValidationCallback(ValidateServerCertificate);
                // select the local secure socket layer (SSL) certificate used for authentication
                var localCertificateCallback = new LocalCertificateSelectionCallback(CertificateSelectionCallback);

                SslStream sslStream = new SslStream(unsecuredStream, false, userCertificateValidationCallback, localCertificateCallback);
                sslStream.AuthenticateAsClient(serverName, certificateCollection, enabledSSLProtocols, false);
                //  sslStream.AuthenticateAsClient(serverName, certificateCollection, enabledSSLProtocols, true); // client and server runs on different machine 
                StreamReader sr = new StreamReader(sslStream);
                StreamWriter sw = new StreamWriter(sslStream) {AutoFlush = true};
                // enable automatic flushing
                Console.WriteLine("Client authenticated");
                for (int i = 0; i < 5; i++)
                {
                    Console.WriteLine("Enter your message here:");
                    string message = Console.ReadLine();
                    sw.WriteLine(message);
                    string serverAnswer = sr.ReadLine();
                    Console.WriteLine("Server: " + serverAnswer);
                }
                sslStream.Close();
                clientSocket.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                Console.WriteLine("Press Enter to finish the Client ");
                Console.ReadKey();
            }
           
        }

        private static bool ValidateServerCertificate(object sender, X509Certificate serverCertificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Client Sender: " + sender);
            Console.WriteLine("Client server certificate : " + serverCertificate);
            Console.WriteLine("Client Policy errors: " + sslPolicyErrors);

            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                Console.WriteLine("Client validation of server certificate successful.");
                return true;
            }
            Console.WriteLine("Errors in certificate validation:");
            Console.WriteLine(sslPolicyErrors);
            return false;
        }

        private static X509Certificate CertificateSelectionCallback(object sender, string targetHost, X509CertificateCollection localCollection,
                                                                   X509Certificate remoteCertificate, string[] acceptableIssuers)
        {

            return localCollection[0];
        }
    }
}
