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

namespace Client
{
    public partial class Form1 : Form
    {
        Thread authenticationThread;
        bool terminating = false;
        bool connected = false;
        string RSAKey = "";
        byte[] ticket_Buffer;
        byte[] Tplain = new byte[64];
        bool ticket_verified_by_client = false;
        byte[] decryptedAES128 = null;
        bool auth_server_upload_done = false;
        bool auth_server_download_done = true;
        bool download = false;
        string filename;
        Socket clientSocket;
        Socket fileServerSocket;
        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
            richTextBox.ReadOnly = true;
        }

        private void connectButton_Click(object sender, EventArgs e)
        {
            IPAddress ipAddress;
            int port;
            if (textIP.Text != string.Empty && IPAddress.TryParse(textIP.Text, out ipAddress))
            {
                if (textPort.Text != string.Empty && textUsername.Text != string.Empty && textPassword.Text != string.Empty)
                {
                    connectButton.Enabled = false;
                    disconnectButton.Enabled = true;
                    string password = textPassword.Text;
                    //read user private key from predefined file path in specific format
                    string path = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\enc_" + textUsername.Text + "_pub_priv.txt";

                    StreamReader file = new StreamReader(path);
                    
                    
                    string encryrtedKey = file.ReadToEnd();

                    richTextBox.AppendText("1024 RSA KEY: \n");
                    richTextBox.AppendText(encryrtedKey + "\n\n");
                    //check if we can decrypted susccesfully
                    bool check = checkPassword(password, encryrtedKey);

                    if (check == true)
                    {
                        richTextBox.AppendText("Login successful! \n\n");
                        port = Int32.Parse(textPort.Text);
                        connectAuthServer(ipAddress, port);
                        fileServerSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                        fileServerSocket.Connect(textIP.Text, 5353);
                    }
                    else
                    {
                        MessageBox.Show("Wrong passwpord! Please try again. \n", " Client", MessageBoxButtons.OK);
                        richTextBox.AppendText("Wrong passwpord! Please try again. \n\n");
                        connectButton.Enabled = true;
                    }
                    
                }
                else
                {
                    richTextBox.AppendText("Please check inputted username, password, ip and port number. \n\n");
                }
            }
            else
            {
                MessageBox.Show("Wrong ip! Please try again. \n", " Client", MessageBoxButtons.OK);
            }

            
        }

        private void uploadBtn_Click(object sender, EventArgs e)
        {
            download = false;
            string file_message = "ticket_request";
            ASCIIEncoding aEncoding = new ASCIIEncoding();
            byte[] ticket_request_message = aEncoding.GetBytes(file_message);
            clientSocket.Send(ticket_request_message);
        }

        private void downloadBtn_Click(object sender, EventArgs e)
        {
            download = true;
            string file_message = "ticket_request";
            ASCIIEncoding aEncoding = new ASCIIEncoding();
            byte[] ticket_request_message = aEncoding.GetBytes(file_message);
            clientSocket.Send(ticket_request_message);
        }

        private void connectAuthServer(IPAddress IP, int port)
        {
            //create socket and send connection request
            clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                clientSocket.Connect(IP, port);
                connected = true;
                authenticationThread = new Thread(new ThreadStart(Authenticate));
                authenticationThread.Start();
                richTextBox.AppendText("Connected to server.\n\n"); //connection request send
            }
            catch
            {
                richTextBox.AppendText("Could not connect.\n\n");
                connectButton.Enabled = true;
            }
        }
        private void Authenticate()
        {
            string message = textUsername.Text;
            bool authenticated = false;

            while (connected && !terminating)
            {
                try
                {
                    if (authenticated == false) //if we not yet authenticated by authentication server
                    {
                        byte[] buffer = new byte[64];
                        buffer = Encoding.Default.GetBytes(message);
                        clientSocket.Send(buffer);
                        richTextBox.AppendText(message + " username sent\n");

                        //get random key sended by authentication server as a challenge 
                        byte[] bufferRandomKey = new byte[16];
                        clientSocket.Receive(bufferRandomKey);

                        string randomKey = generateHexStringFromByteArray(bufferRandomKey);
                        richTextBox.AppendText("Random Key sent by server: \n" + randomKey + "\n\n");

                        //sign that randomkey by our RSA
                        byte[] signatureRSA = signWithRSA(randomKey, 1024, RSAKey);
                        richTextBox.AppendText(" Signed key: \n " + generateHexStringFromByteArray(signatureRSA) + " \n\n");
                        clientSocket.Send(signatureRSA);

                        //get acknowledgement from authentication server
                        buffer = new byte[64];
                        clientSocket.Receive(buffer);
                        string ackMessage = Encoding.Default.GetString(buffer);
                        ackMessage = ackMessage.Substring(0, ackMessage.IndexOf('\0'));

                        byte[] signedAcknowledgment = new byte[128];
                        clientSocket.Receive(signedAcknowledgment);

                        //check our acknowledge is come from valis server 
                        bool verificationResult = verifySignature(ackMessage, signedAcknowledgment);

                        if (verificationResult == true)
                        {
                            //our server is valid
                            richTextBox.AppendText(ackMessage + "\n\n");

                            if (ackMessage == "Unauthorised client")
                            {
                                authenticated = false;
                                richTextBox.AppendText("authentication false \n\n");
                            }
                            else
                            {
                                authenticated = true;
                                richTextBox.AppendText("authentication true \n\n");
                                byte[] ticket_request_buffer = new byte[64];
                                ticket_request_buffer = Encoding.Default.GetBytes("ticket_request");
                                //clientSocket.Send(buffer); //celal kontrol et
                            }
                        }
                        else
                        {
                            //if server not authenticated
                            richTextBox.AppendText("Invalid authserver signature\n\n");
                            connected = false;
                            clientSocket.Close();
                            clientSocket = null;
                            connectButton.Enabled = true;
                            disconnectButton.Enabled = false;
                            richTextBox.AppendText("Connection terminated.\n");
                        }

                    }
                    else if (!auth_server_upload_done)
                    {
                        //authentication succesful and wait another request from user
                        richTextBox.AppendText("\n\n waiting response from authentication server \n\n");
                        byte[] messageBuffer = new byte[64];
                        clientSocket.Receive(messageBuffer);
                        message = Encoding.Default.GetString(messageBuffer);
                        message = message.Substring(0, message.IndexOf('\0'));
                        if (message == "Authenticated_server_sends_ticket")
                        {
                            byte[] file_Length = new byte[64];
                            clientSocket.Receive(file_Length);
                            string length = Encoding.Default.GetString(file_Length);
                            length = length.Substring(0, length.IndexOf("\0"));
                            int len = System.Convert.ToInt32(length);
                            //verify signature
                            ticket_Buffer = new byte[len];
                            clientSocket.Receive(ticket_Buffer);
                            byte[] ticket_encrytpted = new byte[128];
                            byte[] Ticket_signature = new byte[128];
                            System.Buffer.BlockCopy(ticket_Buffer, 0, Ticket_signature, 0, 128);
                            System.Buffer.BlockCopy(ticket_Buffer, 128, ticket_encrytpted, 0, 128);
                            richTextBox.AppendText(generateHexStringFromByteArray(ticket_encrytpted));
                            Tplain = decryptWithRSA(ticket_encrytpted);
                            richTextBox.AppendText("\n\n Tplain is");
                            richTextBox.AppendText(generateHexStringFromByteArray(Tplain));
                            bool verificationResult = verifyWithRSA(Tplain, 1024, Ticket_signature);

                            if (verificationResult == true)
                            {
                                //our server is valid
                                richTextBox.AppendText("\n\n" + "ticket verified" + "\n\n");
                                //sends ticket to file server
                                ticket_verified_by_client = true;
                                //file server a file_upload_ticket string i ve ticket gonderilecek
                                string file_message = "file_upload_ticket";
                                ASCIIEncoding aEncoding = new ASCIIEncoding();
                                byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                                fileServerSocket.Send(ticket_sended_message);
                                fileServerSocket.Send(file_Length);
                                fileServerSocket.Send(ticket_Buffer);
                                richTextBox.AppendText("ticket sended to file server \n\n");
                                auth_server_upload_done = true;
                            }
                            else
                            {
                                richTextBox.AppendText("Authentication server signature do not verified by client. \n\n");
                            }
                        }
                    }
                    else if(auth_server_upload_done)
                    {
                        richTextBox.AppendText("\n\n waiting for request from file server \n\n");
                        byte[] messageBuffer = new byte[64];
                        fileServerSocket.Receive(messageBuffer);
                        message = Encoding.Default.GetString(messageBuffer);
                        message = message.Substring(0, message.IndexOf('\0'));

                        if (message == "file_server_validate_ticket_for_upload")
                        {
                            richTextBox.AppendText("Fie Server positive ack received");
                            if (download)
                            {
                                richTextBox.AppendText(">> download request recognized.\n");
                                ASCIIEncoding aEncoding = new ASCIIEncoding();
                                byte[] filename_bytes = aEncoding.GetBytes(downloadedFileNameTB.Text);
                                byte[] IV = new byte[16];
                                byte[] session_key = new byte[16];
                                System.Buffer.BlockCopy(Tplain, 0, session_key, 0, 16);
                                System.Buffer.BlockCopy(Tplain, 16, IV, 0, 16);


                                byte[] enc_filename_bytes = encryptWithAES128(filename_bytes, session_key, IV);
                                string file_message = "Downloadfile%" + enc_filename_bytes.Length.ToString();
                                byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                                fileServerSocket.Send(ticket_sended_message);
                                richTextBox.AppendText(">> download file request sended to file server.\n");

                                richTextBox.AppendText("enc filename \n");
                                richTextBox.AppendText(generateHexStringFromByteArray(enc_filename_bytes));
                                fileServerSocket.Send(enc_filename_bytes);
                                richTextBox.AppendText(" \n >> enc file name sended.\n");
                            }
                            else if (!download)
                            {
                                string file_message = "client send file";
                                ASCIIEncoding aEncoding = new ASCIIEncoding();
                                byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                                fileServerSocket.Send(ticket_sended_message);
                                upload_file();
                                auth_server_upload_done = false;
                            }
                        }
                        else if (message == "file_not_exist")
                        {
                            richTextBox.AppendText("Wrong file name, no such file \n\n");
                            auth_server_upload_done = false;
                        }
                        else if (message == "File_server_sends_file")
                        {
                            byte[] IV = new byte[16];
                            byte[] session_key = new byte[16];
                            byte[] HMAC_key = new byte[32];
                            System.Buffer.BlockCopy(Tplain, 0, session_key, 0, 16);
                            System.Buffer.BlockCopy(Tplain, 16, IV, 0, 16);
                            System.Buffer.BlockCopy(Tplain, 32, HMAC_key, 0, 32);

                            byte[] file_Length = new byte[64];
                            fileServerSocket.Receive(file_Length);
                            string length = Encoding.Default.GetString(file_Length);
                            richTextBox.AppendText(">> File package length received.\n");
                            length = length.Substring(0, length.IndexOf("\0"));
                            richTextBox.AppendText(length);
                            richTextBox.AppendText("\n\n");
                            int len = System.Convert.ToInt32(length);
                            byte[] buffer2 = new byte[len];

                            int totalReceived = fileServerSocket.Receive(buffer2);
                            richTextBox.AppendText(totalReceived.ToString());
                            richTextBox.AppendText("\n\n");
                            int received = 0;
                            while (totalReceived < len)
                            {
                                byte[] tempBuffer = new byte[len];
                                received = fileServerSocket.Receive(tempBuffer);
                                Buffer.BlockCopy(tempBuffer, 0, buffer2, totalReceived, received);
                                totalReceived += received;
                            }
                            richTextBox.AppendText(buffer2.Length.ToString());
                            byte[] hmac_value = new byte[32];
                            byte[] encrypted_file = new byte[buffer2.Length - hmac_value.Length];
                            System.Buffer.BlockCopy(buffer2, 32, encrypted_file, 0, encrypted_file.Length);
                            System.Buffer.BlockCopy(buffer2, 0, hmac_value, 0, 32);

                            byte[] file_packet = decryptWithCBCAES128(encrypted_file, session_key, IV);
                            richTextBox.AppendText("\n\n\n\n");
                            richTextBox.AppendText(generateHexStringFromByteArray(file_packet));

                            System.Buffer.BlockCopy(buffer2, 0, hmac_value, 0, 32);
                            richTextBox.AppendText(">> File path is " + pathTB.Text + "\n");

                            string pathString = System.IO.Path.Combine(pathTB.Text, textUsername.Text);
                            System.IO.Directory.CreateDirectory(pathString);

                            richTextBox.AppendText(downloadedFileNameTB.Text);
                            string pathString2 = System.IO.Path.Combine(pathString, downloadedFileNameTB.Text);
                            richTextBox.AppendText(pathString2 + "\n\n");

                            if (generateHexStringFromByteArray(hmac_value) == generateHexStringFromByteArray(applyHMACwithSHA256(file_packet,HMAC_key))) { 
                                File.WriteAllBytes(pathString2, file_packet);
                            
                            richTextBox.AppendText(">> File transfer succesful.\n");
                            }
                            else
                                richTextBox.AppendText("\n\n >> Wrong hmac.\n");
                           auth_server_upload_done = false;
                        }

                    }
                }
                catch
                {
                    if (!terminating)
                    {
                        richTextBox.AppendText("Lost connection to server.\n");
                        disconnectButton.Enabled = false;
                        connectButton.Enabled = true;
                    }
                    if (clientSocket != null)
                    {
                        connected = false;
                        clientSocket.Close();
                        clientSocket = null;
                        RSAKey = "";
                    }
                }
            }
        }

        public void upload_file()
        {
            /////////////////////////////
            byte[] HMAC_key = new byte[32];
            byte[] IV = new byte[16];
            byte[] session_key = new byte[16];
            System.Buffer.BlockCopy(Tplain, 0, session_key, 0, 16);
            System.Buffer.BlockCopy(Tplain, 16, IV, 0, 16);
            System.Buffer.BlockCopy(Tplain, 32, HMAC_key, 0, 32);
            ///
            richTextBox.AppendText("Session key :== \n");
            richTextBox.AppendText(generateHexStringFromByteArray(session_key));
            richTextBox.AppendText("\n\n");

            richTextBox.AppendText("Session key :== \n");
            richTextBox.AppendText(generateHexStringFromByteArray(IV));
            richTextBox.AppendText("\n\n");

            richTextBox.AppendText("Session key :== \n");
            richTextBox.AppendText(generateHexStringFromByteArray(HMAC_key));
            richTextBox.AppendText("\n\n");

            ///
            byte[] bytes_file = System.IO.File.ReadAllBytes(BrowseTextPath.Text);
            byte[] hmac_bytes_file = applyHMACwithSHA256(bytes_file, HMAC_key);

            richTextBox.AppendText(hmac_bytes_file.Length.ToString());
            richTextBox.AppendText("\n\n");

            ASCIIEncoding aEncoding = new ASCIIEncoding();
            byte[] filename_bytes = aEncoding.GetBytes(filename);
            int file_length = bytes_file.Length;

            byte[] file_packet = new byte[filename_bytes.Length + file_length];

            System.Buffer.BlockCopy(filename_bytes, 0, file_packet, 0, filename_bytes.Length);
            System.Buffer.BlockCopy(bytes_file, 0, file_packet, filename_bytes.Length, bytes_file.Length);
            
            byte[] encrypted_file_packet = encryptWithAES128(bytes_file, session_key, IV);//bytes_file file_packet olacak
            richTextBox.AppendText(encrypted_file_packet.Length.ToString());
            richTextBox.AppendText("\n\n");

            byte[] final_packet = new byte[encrypted_file_packet.Length + hmac_bytes_file.Length];
            System.Buffer.BlockCopy(hmac_bytes_file, 0, final_packet, 0, hmac_bytes_file.Length);
            System.Buffer.BlockCopy(encrypted_file_packet, 0, final_packet, hmac_bytes_file.Length, encrypted_file_packet.Length);
            //final_packet is ready to send
            string file_len = final_packet.Length.ToString();

            richTextBox.AppendText(file_len);
            richTextBox.AppendText("\n\n");

            byte[] file_send_length = Encoding.Default.GetBytes(file_len);
            byte[] container_fileLength = new byte[64];

            Buffer.BlockCopy(file_send_length, 0, container_fileLength, 0, file_send_length.Length);

            fileServerSocket.Send(filename_bytes);
            fileServerSocket.Send(container_fileLength);
            fileServerSocket.Send(final_packet);
            richTextBox.AppendText(">> File succesfully sent.\n");
        }
        private void disconnectButton_Click(object sender, EventArgs e)
        {
            connected = false;
            clientSocket.Close();
            clientSocket = null;
            RSAKey = "";

        }

        private bool checkPassword(string password, string encKey)
        {
            byte[] byteKey = new byte[16];
            byte[] byteIV = new byte[16];
           
            byte[] sha256 = hashWithSHA256(password);
            richTextBox.AppendText("SHA256 result:");
            richTextBox.AppendText(generateHexStringFromByteArray(sha256) + "\n\n");

            //create array for IV and Key
            Array.Copy(sha256, 0, byteKey, 0, 16);
            Array.Copy(sha256, 16, byteIV, 0, 16);

            //print them to rich text box
            richTextBox.AppendText("Key: \n");
            richTextBox.AppendText(generateHexStringFromByteArray(byteKey) + "\n\n");
            richTextBox.AppendText("IV: \n");
            richTextBox.AppendText(generateHexStringFromByteArray(byteIV) + "\n\n");

            //decrypt our private key and determine RSA private key
            byte[] encKeyByte = StringToByteArray(encKey);
            decryptedAES128 = decryptWithAES128(encKeyByte, byteKey, byteIV);

            //check decryption succesful
            if (decryptedAES128 != null)
            {
                RSAKey = Encoding.Default.GetString(decryptedAES128);
                if (RSAKey.IndexOf("<RSAKeyValue>") == 0)
                {
                    richTextBox.AppendText("RSA key: \n");
                    richTextBox.AppendText(stringToHexadecimal(RSAKey) + "\n");
                    return true;
                }
            }
               
            return false;
        }
        static byte[] decryptWithCBCAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CBC;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }
        private bool verifySignature(string message, byte[] signature)
        {
            
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(message);

            //richTextBox.AppendText("Auth Server public ras key: \n" + stringToHexadecimal(authPubRSA) + "\n\n");

            bool result = verifyWithRSA(byteInput, 1024, signature);

            return result;
        }

        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }

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

        static byte[] hashWithSHA256(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA256CryptoServiceProvider sha256Hasher = new SHA256CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha256Hasher.ComputeHash(byteInput);

            return result;
        }
        private byte[] decryptWithRSA(byte[] byteInput)
        {
            //byte[] byteInput = Encoding.Default.GetBytes(input);
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(1024);
            rsaObject.FromXmlString(Encoding.Default.GetString(decryptedAES128));
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
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = StringToByteArray(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
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


        static byte[] decryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            // create AES object from System.Security.Cryptography
            RijndaelManaged aesObject = new RijndaelManaged();
            // since we want to use AES-128
            aesObject.KeySize = 128;
            // block size of AES is 128 bits
            aesObject.BlockSize = 128;
            // mode -> CipherMode.*
            aesObject.Mode = CipherMode.CFB;
            // feedback size should be equal to block size
            aesObject.FeedbackSize = 128;
            // set the key
            aesObject.Key = key;
            // set the IV
            aesObject.IV = IV;
            // create an encryptor with the settings provided
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;

            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e) // if encryption fails
            {
                Console.WriteLine(e.Message); // display the cause
            }

            return result;
        }

        static bool verifyWithRSA(byte[] byteInput, int algoLength, byte[] signature)
        {
            // create RSA object from System.Security.Cryptography
            //read auth server public key from specific file
            string pathAuthPub = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\auth_server_pub.txt";

            StreamReader file = new StreamReader(pathAuthPub);
            string xmlString = file.ReadToEnd();
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
            if (MessageBox.Show("Do you want to exit?", "Client",
                MessageBoxButtons.YesNo) == DialogResult.No)
            {
                e.Cancel = true;
            }
            else
            {
                RSAKey = "";
                connected = false;
                terminating = true;
                Environment.Exit(0);
            }
        }

        private void browseBtn_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                BrowseTextPath.Text = openFileDialog1.FileName;
                filename = openFileDialog1.SafeFileName;
                uploadBtn.Enabled = true;
            }
        }

        static byte[] applyHMACwithSHA256(byte[] byteInput, byte[] key)
        {
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            byte[] result = hmacSHA256.ComputeHash(byteInput);
            return result;
        }

        static byte[] encryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
        {
            RijndaelManaged aesObject = new RijndaelManaged();
            aesObject.KeySize = 128;
            aesObject.BlockSize = 128;
            aesObject.Mode = CipherMode.CBC;
            aesObject.FeedbackSize = 128;
            aesObject.Key = key;
            aesObject.IV = IV;
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;
            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return result;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                pathTB.Text = folderBrowserDialog1.SelectedPath;
            }
        }
    }

}
