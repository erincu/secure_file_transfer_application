namespace Client
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.connectButton = new System.Windows.Forms.Button();
            this.textUsername = new System.Windows.Forms.TextBox();
            this.textPassword = new System.Windows.Forms.TextBox();
            this.textPort = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.textIP = new System.Windows.Forms.TextBox();
            this.richTextBox = new System.Windows.Forms.RichTextBox();
            this.disconnectButton = new System.Windows.Forms.Button();
            this.label5 = new System.Windows.Forms.Label();
            this.uploadBtn = new System.Windows.Forms.Button();
            this.browseBtn = new System.Windows.Forms.Button();
            this.BrowseTextPath = new System.Windows.Forms.TextBox();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.label6 = new System.Windows.Forms.Label();
            this.downloadBtn = new System.Windows.Forms.Button();
            this.downloadedFileNameTB = new System.Windows.Forms.TextBox();
            this.pathTB = new System.Windows.Forms.TextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.SuspendLayout();
            // 
            // connectButton
            // 
            this.connectButton.Location = new System.Drawing.Point(661, 133);
            this.connectButton.Name = "connectButton";
            this.connectButton.Size = new System.Drawing.Size(100, 23);
            this.connectButton.TabIndex = 0;
            this.connectButton.Text = "CONNECT";
            this.connectButton.UseVisualStyleBackColor = true;
            this.connectButton.Click += new System.EventHandler(this.connectButton_Click);
            // 
            // textUsername
            // 
            this.textUsername.Location = new System.Drawing.Point(661, 81);
            this.textUsername.Name = "textUsername";
            this.textUsername.Size = new System.Drawing.Size(100, 20);
            this.textUsername.TabIndex = 3;
            this.textUsername.Text = "c1";
            // 
            // textPassword
            // 
            this.textPassword.Location = new System.Drawing.Point(661, 107);
            this.textPassword.Name = "textPassword";
            this.textPassword.Size = new System.Drawing.Size(100, 20);
            this.textPassword.TabIndex = 4;
            this.textPassword.Text = "pass1";
            // 
            // textPort
            // 
            this.textPort.Location = new System.Drawing.Point(661, 55);
            this.textPort.Name = "textPort";
            this.textPort.Size = new System.Drawing.Size(100, 20);
            this.textPort.TabIndex = 5;
            this.textPort.Text = "8080";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(590, 32);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(58, 13);
            this.label1.TabIndex = 8;
            this.label1.Text = "IP Address";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(590, 62);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(26, 13);
            this.label2.TabIndex = 9;
            this.label2.Text = "Port";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(590, 88);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(53, 13);
            this.label3.TabIndex = 10;
            this.label3.Text = "username";
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(590, 114);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(52, 13);
            this.label4.TabIndex = 11;
            this.label4.Text = "password";
            // 
            // textIP
            // 
            this.textIP.Location = new System.Drawing.Point(661, 29);
            this.textIP.Name = "textIP";
            this.textIP.Size = new System.Drawing.Size(100, 20);
            this.textIP.TabIndex = 13;
            this.textIP.Text = "159.20.95.13";
            // 
            // richTextBox
            // 
            this.richTextBox.Location = new System.Drawing.Point(51, 32);
            this.richTextBox.Name = "richTextBox";
            this.richTextBox.Size = new System.Drawing.Size(360, 284);
            this.richTextBox.TabIndex = 14;
            this.richTextBox.Text = "";
            // 
            // disconnectButton
            // 
            this.disconnectButton.Enabled = false;
            this.disconnectButton.Location = new System.Drawing.Point(661, 182);
            this.disconnectButton.Name = "disconnectButton";
            this.disconnectButton.Size = new System.Drawing.Size(100, 23);
            this.disconnectButton.TabIndex = 15;
            this.disconnectButton.Text = "DISCONNECT";
            this.disconnectButton.UseVisualStyleBackColor = true;
            this.disconnectButton.Click += new System.EventHandler(this.disconnectButton_Click);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(470, 62);
            this.label5.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(0, 13);
            this.label5.TabIndex = 18;
            // 
            // uploadBtn
            // 
            this.uploadBtn.Location = new System.Drawing.Point(432, 290);
            this.uploadBtn.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.uploadBtn.Name = "uploadBtn";
            this.uploadBtn.Size = new System.Drawing.Size(85, 23);
            this.uploadBtn.TabIndex = 19;
            this.uploadBtn.Text = "Upload";
            this.uploadBtn.UseVisualStyleBackColor = true;
            this.uploadBtn.Click += new System.EventHandler(this.uploadBtn_Click);
            // 
            // browseBtn
            // 
            this.browseBtn.Location = new System.Drawing.Point(520, 290);
            this.browseBtn.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.browseBtn.Name = "browseBtn";
            this.browseBtn.Size = new System.Drawing.Size(82, 23);
            this.browseBtn.TabIndex = 20;
            this.browseBtn.Text = "Browse";
            this.browseBtn.UseVisualStyleBackColor = true;
            this.browseBtn.Click += new System.EventHandler(this.browseBtn_Click);
            // 
            // BrowseTextPath
            // 
            this.BrowseTextPath.Location = new System.Drawing.Point(428, 264);
            this.BrowseTextPath.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.BrowseTextPath.Name = "BrowseTextPath";
            this.BrowseTextPath.Size = new System.Drawing.Size(177, 20);
            this.BrowseTextPath.TabIndex = 21;
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(430, 162);
            this.label6.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(117, 13);
            this.label6.TabIndex = 22;
            this.label6.Text = "Downloaded File Name";
            // 
            // downloadBtn
            // 
            this.downloadBtn.Location = new System.Drawing.Point(432, 217);
            this.downloadBtn.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.downloadBtn.Name = "downloadBtn";
            this.downloadBtn.Size = new System.Drawing.Size(172, 23);
            this.downloadBtn.TabIndex = 23;
            this.downloadBtn.Text = "Download";
            this.downloadBtn.UseVisualStyleBackColor = true;
            this.downloadBtn.Click += new System.EventHandler(this.downloadBtn_Click);
            // 
            // downloadedFileNameTB
            // 
            this.downloadedFileNameTB.Location = new System.Drawing.Point(428, 185);
            this.downloadedFileNameTB.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.downloadedFileNameTB.Name = "downloadedFileNameTB";
            this.downloadedFileNameTB.Size = new System.Drawing.Size(174, 20);
            this.downloadedFileNameTB.TabIndex = 24;
            // 
            // pathTB
            // 
            this.pathTB.Location = new System.Drawing.Point(428, 133);
            this.pathTB.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.pathTB.Name = "pathTB";
            this.pathTB.Size = new System.Drawing.Size(174, 20);
            this.pathTB.TabIndex = 25;
            this.pathTB.Text = "C:\\Users\\erincu\\Desktop\\download files";
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(428, 97);
            this.button1.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(158, 20);
            this.button1.TabIndex = 26;
            this.button1.Text = "Download Path";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(779, 345);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.pathTB);
            this.Controls.Add(this.downloadedFileNameTB);
            this.Controls.Add(this.downloadBtn);
            this.Controls.Add(this.label6);
            this.Controls.Add(this.BrowseTextPath);
            this.Controls.Add(this.browseBtn);
            this.Controls.Add(this.uploadBtn);
            this.Controls.Add(this.label5);
            this.Controls.Add(this.disconnectButton);
            this.Controls.Add(this.richTextBox);
            this.Controls.Add(this.textIP);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textPort);
            this.Controls.Add(this.textPassword);
            this.Controls.Add(this.textUsername);
            this.Controls.Add(this.connectButton);
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button connectButton;
        private System.Windows.Forms.TextBox textUsername;
        private System.Windows.Forms.TextBox textPassword;
        private System.Windows.Forms.TextBox textPort;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox textIP;
        private System.Windows.Forms.RichTextBox richTextBox;
        private System.Windows.Forms.Button disconnectButton;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Button uploadBtn;
        private System.Windows.Forms.Button browseBtn;
        private System.Windows.Forms.TextBox BrowseTextPath;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Button downloadBtn;
        private System.Windows.Forms.TextBox downloadedFileNameTB;
        private System.Windows.Forms.TextBox pathTB;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
    }
}

