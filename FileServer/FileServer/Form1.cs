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

namespace FileServer
{
   
    public partial class Form1 : Form
    {
        bool terminating = false;
        bool listening = false;
        byte[] Tplain = null;
        bool ticket_verified_by_FS = false;
        byte[] HMAC_key = new byte[32];
        byte[] IV = new byte[16];
        byte[] session_key = new byte[16];
        byte[] username = null;
        int counter = 1;

        Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        List<Socket> socketList = new List<Socket>();
        List<string> clientList = new List<string>();
        public Form1()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(Form1_FormClosing);
            InitializeComponent();
        }

        private void listenBtn_Click(object sender, EventArgs e)
        {
            int serverPort;
            Thread acceptThread;

            if (Int32.TryParse(portTB.Text, out serverPort))
            {
                serverSocket.Bind(new IPEndPoint(IPAddress.Any, serverPort));
                serverSocket.Listen(3);

                listening = true;
                listenBtn.Enabled = false;
                acceptThread = new Thread(new ThreadStart(Accept));
                acceptThread.Start();

                richTB.AppendText("Started listening on port: " + serverPort + "\n");
            }
            else
            {
                richTB.AppendText("Check port.\n");
            }
        }

        private void Accept()
        {
            while (listening)
            {
                try
                {
                    socketList.Add(serverSocket.Accept());
                    richTB.AppendText("Client connect request recognized.\n");

                    Thread receiveThread;
                    receiveThread = new Thread(new ThreadStart(Receive));
                    receiveThread.Start();
                }
                catch
                {
                    if (terminating)
                        listening = false;
                    else
                        richTB.AppendText("The socket stopped working.\n");
                }
            }
        }

        private void Receive()
        {
            Socket client = socketList[socketList.Count - 1];
            bool connected = true;
            while (connected && !terminating)
            {
                try
                {
                    Byte[] buffer = new byte[64];
                    int rec = client.Receive(buffer);
                    if (rec <= 0)
                    {
                        throw new SocketException();
                    }
                    string client_message = Encoding.Default.GetString(buffer);
                    client_message = client_message.Substring(0, client_message.IndexOf("\0"));

                    if (client_message == "file_upload_ticket")
                    {

                        byte[] file_Length = new byte[64];
                        client.Receive(file_Length);
                        string length = Encoding.Default.GetString(file_Length);
                        length = length.Substring(0, length.IndexOf("\0"));
                        int len = System.Convert.ToInt32(length);
                        //verify signature
                        byte[] ticket_Buffer = new byte[len];
                        client.Receive(ticket_Buffer);
                        byte[] ticket_encrytpted = new byte[128];
                        byte[] Ticket_signature = new byte[128];
                        System.Buffer.BlockCopy(ticket_Buffer, 0, Ticket_signature, 0, 128);
                        System.Buffer.BlockCopy(ticket_Buffer, 256, ticket_encrytpted, 0, 128);
                        richTB.AppendText(generateHexStringFromByteArray(ticket_encrytpted));
                        Tplain = decryptWithRSA(ticket_encrytpted);
                        richTB.AppendText("\n\n Tplain is");
                        richTB.AppendText(generateHexStringFromByteArray(Tplain));
                        bool verificationResult = verifyWithRSA(Tplain, 1024, Ticket_signature);

                        if (verificationResult == true)
                        {
                            //our server is valid
                            richTB.AppendText("\n\n" + "ticket verified" + "\n\n");
                            //sends ticket to file server
                            ticket_verified_by_FS = true;
                            username = new byte[Tplain.Length - (session_key.Length + HMAC_key.Length + IV.Length)];
                            System.Buffer.BlockCopy(Tplain, 0, session_key, 0, 16);
                            System.Buffer.BlockCopy(Tplain, 16, IV, 0, 16);
                            System.Buffer.BlockCopy(Tplain, 32, HMAC_key, 0, 32);
                            System.Buffer.BlockCopy(Tplain, 64, username, 0, username.Length);

                            richTB.AppendText("\n username is : ");
                            richTB.AppendText(generateHexStringFromByteArray(username));
                            string file_message = "file_server_validate_ticket_for_upload";
                            ASCIIEncoding aEncoding = new ASCIIEncoding();
                            byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                            client.Send(ticket_sended_message);
                        }
                        else
                        {
                            richTB.AppendText("Authentication server signature do not verified by client. \n\n");
                        }
                    }

                    else if (client_message == "client send file")
                    {
                        richTB.AppendText("\n Client send file request received \n\n");
                        byte[] filename_byte = new byte[64];
                        client.Receive(filename_byte);
                        string filename = Encoding.Default.GetString(filename_byte);
                        filename = filename.Substring(0, filename.IndexOf("\0"));
                        byte[] file_Length = new byte[64];
                        client.Receive(file_Length);
                        string length = Encoding.Default.GetString(file_Length);
                        richTB.AppendText(">> File package length received.\n");
                        length = length.Substring(0, length.IndexOf("\0"));
                        richTB.AppendText(length);
                        richTB.AppendText("\n\n");
                        int len = System.Convert.ToInt32(length);
                        byte[] buffer2 = new byte[len];
                        int totalReceived = client.Receive(buffer2);
                        richTB.AppendText(totalReceived.ToString());
                        richTB.AppendText("\n\n");
                        int received = 0;

                        while (totalReceived < len)
                        {
                            byte[] tempBuffer = new byte[len];
                            received = client.Receive(tempBuffer);
                            Buffer.BlockCopy(tempBuffer, 0, buffer2, totalReceived, received);
                            totalReceived += received;
                            richTB.AppendText(received.ToString());
                            richTB.AppendText("\n\n");
                        }

                        byte[] hmac_value = new byte[32];
                        byte[] encrypted_file = new byte[buffer2.Length - 32];
                        System.Buffer.BlockCopy(buffer2, 32, encrypted_file, 0, encrypted_file.Length);
                        System.Buffer.BlockCopy(buffer2, 0, hmac_value, 0, 32);
                        byte[] plain_file = decryptWithAES128(encrypted_file, session_key, IV);

                        System.Buffer.BlockCopy(buffer2, 0, hmac_value, 0, 32);
                        System.Buffer.BlockCopy(buffer2, 32, encrypted_file, 0, encrypted_file.Length);
                        richTB.AppendText(">> File path is " + pathTB.Text + "\n");

                        string nameOfuser = generateHexStringFromByteArray(username);
                        richTB.AppendText(nameOfuser);
                        string pathString = System.IO.Path.Combine(pathTB.Text, nameOfuser);

                        System.IO.Directory.CreateDirectory(pathString);

                        richTB.AppendText(filename);
                        string pathString2 = System.IO.Path.Combine(pathString, filename);

                        if (generateHexStringFromByteArray(hmac_value) == generateHexStringFromByteArray(applyHMACwithSHA256(plain_file, HMAC_key)))
                        {
                            File.WriteAllBytes(pathString2, plain_file);
                            richTB.AppendText(">> File transfer succesful.\n");
                        }
                        else
                            richTB.AppendText("\n\n >> Wrong hmac.\n");
                        counter++;
                    }
                    else if (client_message.IndexOf("D") == 0)
                    {
                        string[] words = client_message.Split('%');
                        
                        string file_leng = words[1];
                        int len = System.Convert.ToInt32(file_leng);
                        byte [] enc_filename = new byte [len];
                        richTB.AppendText("Downlodfile request received \n");
                        client.Receive(enc_filename);

                        richTB.AppendText("enc file name is: \n");
                        richTB.AppendText(generateHexStringFromByteArray(enc_filename));

                        byte[] dec_filename = decryptWithAES128(enc_filename,session_key,IV);
                        string filename = Encoding.Default.GetString(dec_filename);
                        //filename = filename.Substring(0, filename.IndexOf("\0"));
                        richTB.AppendText("downloaded file name is: \n");
                        richTB.AppendText(filename);
                        string nameOfuser = generateHexStringFromByteArray(username);
                        string pathString = System.IO.Path.Combine(pathTB.Text, nameOfuser);
                        string ownerfileLocation = System.IO.Path.Combine(pathString, filename);
                        if (!File.Exists(ownerfileLocation))
                        {
                            richTB.AppendText(" \n Unrecognized download request \n");
                            string file_message = "file_not_exist";
                            ASCIIEncoding aEncoding = new ASCIIEncoding();
                            byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                            client.Send(ticket_sended_message);
                        }
                        else
                        {
                            string file_message = "File_server_sends_file";
                            ASCIIEncoding aEncoding = new ASCIIEncoding();
                            byte[] ticket_sended_message = aEncoding.GetBytes(file_message);
                            client.Send(ticket_sended_message);


                            byte[] bytes_file = System.IO.File.ReadAllBytes(ownerfileLocation);

                            byte[] hmac_bytes_file = applyHMACwithSHA256(bytes_file, HMAC_key);

                            byte[] file_packet = new byte[dec_filename.Length + bytes_file.Length];
                            System.Buffer.BlockCopy(dec_filename, 0, file_packet, 0, dec_filename.Length);
                            System.Buffer.BlockCopy(bytes_file, 0, file_packet, dec_filename.Length, bytes_file.Length);

                            byte[] encrypted_file_packet = encryptWithAES128(bytes_file, session_key, IV);
                            richTB.AppendText("\n\n");

                           

                            byte[] final_packet = new byte[encrypted_file_packet.Length + hmac_bytes_file.Length];
                            System.Buffer.BlockCopy(hmac_bytes_file, 0, final_packet, 0, hmac_bytes_file.Length);
                            System.Buffer.BlockCopy(encrypted_file_packet, 0, final_packet, hmac_bytes_file.Length, encrypted_file_packet.Length);
                            //final_packet is ready to send


                            int file_length = final_packet.Length;
                            string file_len = file_length.ToString();
                            byte[] file_send_length = Encoding.Default.GetBytes(file_len);
                            byte[] container_fileLength = new byte[64];
                            Buffer.BlockCopy(file_send_length, 0, container_fileLength, 0, file_send_length.Length);
                            client.Send(container_fileLength);
                            //richTB.AppendText("\n\n "+ file_len);
                            client.Send(final_packet);

                            //richTB.AppendText(generateHexStringFromByteArray(file_packet));
                            richTB.AppendText(">> File succesfully sent.\n");
                        }
                    }
                }
                catch
                {

                }
            }
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
        static byte[] decryptWithAES128(byte[] byteInput, byte[] key, byte[] IV)
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
        static byte[] applyHMACwithSHA256(byte[] byteInput, byte[] key)
        {
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            byte[] result = hmacSHA256.ComputeHash(byteInput);
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
        static byte[] decryptWithRSA(byte[] byteInput)
        {
            //byte[] byteInput = Encoding.Default.GetBytes(input);
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(1024);
            string pathAuthPub = @"C:\Users\erincu\Desktop\CS432 project related\CS432_Project_Spring17\CS432ProjectKeyFiles\file_server_pub_priv.txt";

            StreamReader file = new StreamReader(pathAuthPub);
            string xmlString = file.ReadToEnd();
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
        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
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

        private void browseBtn_Click(object sender, EventArgs e)
        {
            if (folderBrowserDialog1.ShowDialog() == DialogResult.OK)
            {
                pathTB.Text = folderBrowserDialog1.SelectedPath;
            }
        }
    }
}
