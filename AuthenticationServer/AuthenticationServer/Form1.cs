using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace AuthenticationServer
{
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool listening = false;

        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        List<Socket> socketList = new List<Socket>();
        List<string> clientList = new List<string>();

        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private IPAddress GetLocalIp()
        {
            IPHostEntry hostIP = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in hostIP.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                    return ip;
            }
            return hostIP.AddressList[0];
        }
        //Auth server start to listen port
        private void listenButton_Click(object sender, EventArgs e)
        {
            int serverPort;
            Thread acceptThread;

            if (Int32.TryParse(textPort.Text, out serverPort))
            {
                serverSocket.Bind(new IPEndPoint(GetLocalIp(), serverPort));
                serverSocket.Listen(3);
                listening = true;
                listenButton.Enabled = false;
                acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();

                richTextBox.AppendText("Started listening on port: " + serverPort + "\n");
            }
            else
            {
                richTextBox.AppendText("Check port.\n");
            }
        }

        private void Accept()
        {
            while (listening)
            {
                try
                {
                    socketList.Add(serverSocket.Accept());
                    richTextBox.AppendText("Client connect request recognized.\n");

                    Thread receiveThread;
                    receiveThread = new Thread(new ThreadStart(Authenticate));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                        listening = false;
                    else
                        richTextBox.AppendText("The socket stopped working.\n");
                }
            }
        }

        private void Authenticate()
        {
            Socket s = socketList[socketList.Count - 1];
            bool connected = true;
            bool authenticated = false;
            string username = "";

            while (connected && !terminating)
            {
                try
                {
                    //if client has not been authorized yet
                    if (authenticated == false)
                    {
                        //take username from client
                        byte[] buffer = new byte[64];
                        s.Receive(buffer);

                        //add username to client list
                        username = Encoding.Default.GetString(buffer);
                        username = username.Substring(0, username.IndexOf('\0'));
                        //check dublicate user
                        if (clientList.Contains(username))
                        {
                            richTextBox.AppendText("Dublicate username. Connection terminated. \n");
                            s.Close();
                            socketList.Remove(s);
                            connected = false;
                        }
                        else
                        {
                            clientList.Add(username);

                            //Challenge-Response Protocol
                            //create randomkey and send to client
                            string randomKey = RandomKeyGenerator(128);
                            richTextBox.AppendText("Random Key has been created: \n");
                            //richTextBox.AppendText(randomKey + "\n\n");
                            byte[] bufferRandomKey = StringToByteArray(randomKey);
                            s.Send(bufferRandomKey);

                            //take signed randomkey from client
                            byte[] signedKey = new byte[128];
                            s.Receive(signedKey);
                            //richTextBox.AppendText("signed Key " + generateHexStringFromByteArray(signedKey) + "\n\n");
                            richTextBox.AppendText("Signed random key received. \n");

                            //verifying signature & positive or negative acknowledgement message
                            bool verificationResult = verifySignature(username, randomKey, signedKey);
                            byte[] signedAcknowledgement;

                            //positive acknowledgement
                            if (verificationResult == true)
                            {
                                string ackMessage = "You authenticated successfully";
                                buffer = Encoding.Default.GetBytes(ackMessage);
                                s.Send(buffer);
                                signedAcknowledgement = signAcknowlegment(ackMessage);
                                s.Send(signedAcknowledgement);
                                //richTextBox.AppendText("Signed acknowledgement message: \n" + generateHexStringFromByteArray(signedAcknowledgement) + "\n\n");

                                richTextBox.AppendText(username + " authenticated successfully\n\n");
                                byte[] Ticket = createTicket(username);
                                authenticated = true;
                            }
                            else //negative acknowledgement
                            {
                                string ackMessage = "Unauthorised client";
                                buffer = Encoding.Default.GetBytes(ackMessage);
                                richTextBox.AppendText(ackMessage + "\n\n");
                                s.Send(buffer);
                                signedAcknowledgement = signAcknowlegment(ackMessage);
                                s.Send(signedAcknowledgement);
                                richTextBox.AppendText("Signed acknowledgement message: \n" + generateHexStringFromByteArray(signedAcknowledgement) + "\n\n");

                                //if sign verification fails, socket is closed and client is removed from client list
                                s.Close();
                                clientList.Remove(username);
                                socketList.Remove(s);
                                connected = false;

                                richTextBox.AppendText("Connection terminated!! \n");
                            }
                        }
                    }
                    else //if client passes challange-response protocol successfully, server waiting for another requests
                    {
                        richTextBox.AppendText("ticket request waiting ");
                        byte[] messageBuffer = new byte[64];
                        s.Receive(messageBuffer);
                        string message = Encoding.Default.GetString(messageBuffer);
                        richTextBox.AppendText(message + " bu geldi");
                        message = message.Substring(0, message.IndexOf('\0'));
                        if (message == "ticket_request")
                        {
                            string mes = "Authenticated_server_sends_ticket";
                            ASCIIEncoding aEncoding = new ASCIIEncoding();
                            byte[] sending_message = aEncoding.GetBytes(mes);
                            s.Send(sending_message);
                            //create ticket
                            byte[] Ticket = createTicket(username);
                            byte[] Ticket_lenght = GetLength(Ticket);
                            s.Send(Ticket_lenght);
                            s.Send(Ticket);
                            richTextBox.AppendText("ticket sended to " + username);
                        }
                        else if(message == "disconnect")
                        {
                            s.Close();
                            clientList.Remove(username);
                            socketList.Remove(s);
                            connected = false;
                        }
                    }
                }
                catch
                {
                    if (!terminating)
                        richTextBox.AppendText(username + " has disconnected.\n");

                    s.Close();
                    clientList.Remove(username);
                    socketList.Remove(s);
                    connected = false;
                }
            }
        }

        //print client list
        private void clientButton_Click(object sender, EventArgs e)
        {
            richTextBox.AppendText("client list: \n");
            for (int i = 0; i < clientList.Count; i++)
            {
                richTextBox.AppendText(clientList[i] + "\n");
            }
        }

        private byte [] GetLength(byte [] bytes_file)
        {
            int ticket_length = bytes_file.Length;
            string ticket_len = ticket_length.ToString();
            byte[] file_send_length = Encoding.Default.GetBytes(ticket_len);
            byte[] container_ticket_length = new byte[64];
            Buffer.BlockCopy(file_send_length, 0, container_ticket_length, 0, file_send_length.Length);
            return container_ticket_length;
        }
        //checks client signature is true of false
        private bool verifySignature(string username, string key, byte[] signature)
        {
            string pathUserPub = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\";

             pathUserPub += username + "_pub.txt";
            richTextBox.AppendText(pathUserPub + "\n\n ");

            StreamReader file = new StreamReader(pathUserPub);
            string userPubRSA = file.ReadToEnd();
            // convert input string to byte array
            byte[] byteInput = StringToByteArray(key);

            //richTextBox.AppendText(username + " public rsa: " + stringToHexadecimal(userPubRSA) + "\n\n");
            bool result = verifyWithRSA(byteInput, 1024, userPubRSA, signature);
            
            return result;
        }

        //auth server signs the acknowledgement message
        private byte[] signAcknowlegment(string message)
        {
            //Read RSA key from file
            string pathAuthServerPriv = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\auth_server_pub_priv.txt";
            StreamReader file = new StreamReader(pathAuthServerPriv);
            string authServerRSA = file.ReadToEnd();

            //write RSA key to byte array
            byte[] byteInput = Encoding.Default.GetBytes(message);
            byte[] signedMessage = signWithRSA(byteInput);

            return signedMessage;
        }


        private static string RandomKeyGenerator(int bit)
        {
            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
            bit = bit / 8;
            byte[] randomNumber = new byte[bit];

            // Fill the array with a random value.
            rngCsp.GetBytes(randomNumber);

            // Display the resulting random number as a hexadecimal string.
            string hexResult = (generateHexStringFromByteArray(randomNumber));
            Console.WriteLine(hexResult);

            return hexResult;
        }

        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

        //convert string to hexadecimal string
        static string stringToHexadecimal(string input)
        {
            byte[] byteInput = Encoding.Default.GetBytes(input);
            string hexString = generateHexStringFromByteArray(byteInput);
            return hexString.Replace("-", "");
        }

        public static byte[] StringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        // RSA encryption with varying bit length
        static byte[] encryptWithFileServer(byte[] byteInput)
        {
            string pathFileServerPriv = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\file_server_pub.txt";
            StreamReader file = new StreamReader(pathFileServerPriv);
            string xmlString = file.ReadToEnd();
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(1024);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        // RSA encryption with varying bit length
        static byte[] encryptWithClient(byte[] byteInput, string username)
        {
            string pathUserPub = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\";
            pathUserPub += username + "_pub.txt";
            StreamReader file = new StreamReader(pathUserPub);
            string xmlString = file.ReadToEnd();
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(1024);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        static byte[] decryptWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        static byte[] signWithRSA(byte[] byteInput)
        {
            // create RSA object from System.Security.Cryptography
            string pathAuthServerPriv = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\auth_server_pub_priv.txt";
            StreamReader file = new StreamReader(pathAuthServerPriv);
            string authServerRSA = file.ReadToEnd();
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(1024);
            // set RSA object with xml string
            rsaObject.FromXmlString(authServerRSA);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA256");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        static bool verifyWithRSA(byte[] byteInput, int algoLength, string xmlString, byte[] signature)
        {
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA256", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }

        private void Form1_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (MessageBox.Show("Do you want to exit?", "Server",
                MessageBoxButtons.YesNo) == DialogResult.No)
            {
                e.Cancel = true;
            }
            else
            {
                listening = false;
                terminating = true;
                Environment.Exit(0);
            }
        }

        private byte[] createTicket(string username)
        {
            string ticket_sessionKey = RandomKeyGenerator(128);
            byte[] buffer_ticket_sessionKey = StringToByteArray(ticket_sessionKey);
            string ticket_IV = RandomKeyGenerator(128);
            byte[] buffer_ticket_IV = StringToByteArray(ticket_IV);
            string ticket_HMAC_Key = RandomKeyGenerator(256);
            byte[] buffer_ticket_HMAC_Key = StringToByteArray(ticket_HMAC_Key);
            byte[] buffer_username = StringToByteArray(username);
            byte[] Tplain = new byte[buffer_ticket_sessionKey.Length + buffer_ticket_IV.Length + buffer_ticket_HMAC_Key.Length+buffer_username.Length];
            System.Buffer.BlockCopy(buffer_ticket_sessionKey, 0, Tplain, 0, buffer_ticket_sessionKey.Length);
            System.Buffer.BlockCopy(buffer_ticket_IV, 0, Tplain, buffer_ticket_sessionKey.Length, buffer_ticket_IV.Length);
            System.Buffer.BlockCopy(buffer_ticket_HMAC_Key, 0, Tplain, buffer_ticket_sessionKey.Length + buffer_ticket_IV.Length, buffer_ticket_HMAC_Key.Length);
            System.Buffer.BlockCopy(buffer_username,0,Tplain, buffer_ticket_sessionKey.Length + buffer_ticket_IV.Length + buffer_ticket_HMAC_Key.Length,buffer_username.Length);

            richTextBox.AppendText("Tplain :== \n");
            richTextBox.AppendText(generateHexStringFromByteArray(Tplain));
            richTextBox.AppendText("\n\n");
            

            richTextBox.AppendText("Session key :== \n");
            richTextBox.AppendText(ticket_sessionKey);
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(ticket_sessionKey.Length.ToString());

            richTextBox.AppendText("IV :== \n");
            richTextBox.AppendText(ticket_IV);
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(ticket_IV.Length.ToString());

            richTextBox.AppendText("HMAC key :== \n");
            richTextBox.AppendText(ticket_HMAC_Key);
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(ticket_HMAC_Key.Length.ToString());

            richTextBox.AppendText(generateHexStringFromByteArray(Tplain));
            richTextBox.AppendText("\n\n");
            byte[] Tplain_signed = signWithRSA(Tplain);
            byte[] Tplain_enc_PubC = encryptWithClient(Tplain, username);
            byte[] Tplain_enc_PubFS = encryptWithFileServer(Tplain);
            byte[] Ticket_final = new byte[Tplain_signed.Length + Tplain_enc_PubC.Length + Tplain_enc_PubFS.Length];


            richTextBox.AppendText(Tplain_signed.Length.ToString());
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(Tplain_enc_PubC.Length.ToString());
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(Tplain_enc_PubFS.Length.ToString());
            richTextBox.AppendText("\n\n");
            richTextBox.AppendText(Ticket_final.Length.ToString());
            richTextBox.AppendText("\n\n");


            ////sig - A
            richTextBox.AppendText("ticket signature is : \n");
            //string A = generateHexStringFromByteArray(Tplain_signed);
            //richTextBox.AppendText(A);
            //richTextBox.AppendText("\n\n");
            ////client encrypted - B
            richTextBox.AppendText("ticket encrypted is : \n");
            string B = generateHexStringFromByteArray(Tplain_enc_PubC);
            richTextBox.AppendText(B);
            richTextBox.AppendText("\n\n");
            ////fs encrypted - C
            richTextBox.AppendText("ticket file server encr is: \n");
            //string C = generateHexStringFromByteArray(Tplain_enc_PubC);
            //richTextBox.AppendText(C);
            //richTextBox.AppendText("\n\n");

            System.Buffer.BlockCopy(Tplain_signed, 0, Ticket_final, 0, Tplain_signed.Length);
            System.Buffer.BlockCopy(Tplain_enc_PubC, 0, Ticket_final, Tplain_signed.Length, Tplain_enc_PubC.Length);
            System.Buffer.BlockCopy(Tplain_enc_PubFS, 0, Ticket_final, Tplain_signed.Length + Tplain_enc_PubC.Length, Tplain_enc_PubFS.Length);

            // A || B || C

            string ABC = generateHexStringFromByteArray(Ticket_final);
            richTextBox.AppendText(ABC);
            richTextBox.AppendText("\n\n");
            return Ticket_final;
        }
    }
}

