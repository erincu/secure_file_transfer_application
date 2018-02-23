namespace AuthenticationServer
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
            this.listenButton = new System.Windows.Forms.Button();
            this.portLabel = new System.Windows.Forms.Label();
            this.textPort = new System.Windows.Forms.TextBox();
            this.richTextBox = new System.Windows.Forms.RichTextBox();
            this.clientButton = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // listenButton
            // 
            this.listenButton.BackColor = System.Drawing.SystemColors.Control;
            this.listenButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.listenButton.ForeColor = System.Drawing.SystemColors.ControlText;
            this.listenButton.Location = new System.Drawing.Point(575, 117);
            this.listenButton.Name = "listenButton";
            this.listenButton.Size = new System.Drawing.Size(100, 31);
            this.listenButton.TabIndex = 0;
            this.listenButton.Text = "LISTEN";
            this.listenButton.UseVisualStyleBackColor = false;
            this.listenButton.Click += new System.EventHandler(this.listenButton_Click);
            // 
            // portLabel
            // 
            this.portLabel.AutoSize = true;
            this.portLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.portLabel.Location = new System.Drawing.Point(572, 51);
            this.portLabel.Name = "portLabel";
            this.portLabel.Size = new System.Drawing.Size(32, 16);
            this.portLabel.TabIndex = 1;
            this.portLabel.Text = "Port";
            // 
            // textPort
            // 
            this.textPort.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.textPort.Location = new System.Drawing.Point(575, 80);
            this.textPort.Name = "textPort";
            this.textPort.Size = new System.Drawing.Size(100, 21);
            this.textPort.TabIndex = 3;
            this.textPort.Text = "8080";
            // 
            // richTextBox
            // 
            this.richTextBox.Location = new System.Drawing.Point(53, 50);
            this.richTextBox.Name = "richTextBox";
            this.richTextBox.ReadOnly = true;
            this.richTextBox.Size = new System.Drawing.Size(340, 322);
            this.richTextBox.TabIndex = 4;
            this.richTextBox.Text = "";
            // 
            // clientButton
            // 
            this.clientButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.clientButton.Location = new System.Drawing.Point(575, 178);
            this.clientButton.Name = "clientButton";
            this.clientButton.Size = new System.Drawing.Size(100, 29);
            this.clientButton.TabIndex = 5;
            this.clientButton.Text = "Client List";
            this.clientButton.UseVisualStyleBackColor = true;
            this.clientButton.Click += new System.EventHandler(this.clientButton_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(794, 441);
            this.Controls.Add(this.clientButton);
            this.Controls.Add(this.richTextBox);
            this.Controls.Add(this.textPort);
            this.Controls.Add(this.portLabel);
            this.Controls.Add(this.listenButton);
            this.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button listenButton;
        private System.Windows.Forms.Label portLabel;
        private System.Windows.Forms.TextBox textPort;
        private System.Windows.Forms.RichTextBox richTextBox;
        private System.Windows.Forms.Button clientButton;
    }
}

