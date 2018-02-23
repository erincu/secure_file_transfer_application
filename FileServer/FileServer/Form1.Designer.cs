namespace FileServer
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
            this.listenBtn = new System.Windows.Forms.Button();
            this.portTB = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.richTB = new System.Windows.Forms.RichTextBox();
            this.pathTB = new System.Windows.Forms.TextBox();
            this.browseBtn = new System.Windows.Forms.Button();
            this.folderBrowserDialog1 = new System.Windows.Forms.FolderBrowserDialog();
            this.SuspendLayout();
            // 
            // listenBtn
            // 
            this.listenBtn.Location = new System.Drawing.Point(308, 102);
            this.listenBtn.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.listenBtn.Name = "listenBtn";
            this.listenBtn.Size = new System.Drawing.Size(116, 44);
            this.listenBtn.TabIndex = 0;
            this.listenBtn.Text = "LISTEN";
            this.listenBtn.UseVisualStyleBackColor = true;
            this.listenBtn.Click += new System.EventHandler(this.listenBtn_Click);
            // 
            // portTB
            // 
            this.portTB.Location = new System.Drawing.Point(308, 73);
            this.portTB.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.portTB.Name = "portTB";
            this.portTB.Size = new System.Drawing.Size(118, 20);
            this.portTB.TabIndex = 1;
            this.portTB.Text = "5353";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(316, 42);
            this.label1.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(26, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "Port";
            // 
            // richTB
            // 
            this.richTB.Location = new System.Drawing.Point(20, 42);
            this.richTB.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.richTB.Name = "richTB";
            this.richTB.Size = new System.Drawing.Size(266, 257);
            this.richTB.TabIndex = 3;
            this.richTB.Text = "";
            // 
            // pathTB
            // 
            this.pathTB.Location = new System.Drawing.Point(308, 199);
            this.pathTB.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.pathTB.Name = "pathTB";
            this.pathTB.Size = new System.Drawing.Size(118, 20);
            this.pathTB.TabIndex = 4;
            this.pathTB.Text = "C:\\Users\\erincu\\Desktop\\file server";
            // 
            // browseBtn
            // 
            this.browseBtn.Location = new System.Drawing.Point(438, 199);
            this.browseBtn.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.browseBtn.Name = "browseBtn";
            this.browseBtn.Size = new System.Drawing.Size(60, 33);
            this.browseBtn.TabIndex = 5;
            this.browseBtn.Text = "Browse";
            this.browseBtn.UseVisualStyleBackColor = true;
            this.browseBtn.Click += new System.EventHandler(this.browseBtn_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(504, 352);
            this.Controls.Add(this.browseBtn);
            this.Controls.Add(this.pathTB);
            this.Controls.Add(this.richTB);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.portTB);
            this.Controls.Add(this.listenBtn);
            this.Margin = new System.Windows.Forms.Padding(2, 2, 2, 2);
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button listenBtn;
        private System.Windows.Forms.TextBox portTB;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.RichTextBox richTB;
        private System.Windows.Forms.TextBox pathTB;
        private System.Windows.Forms.Button browseBtn;
        private System.Windows.Forms.FolderBrowserDialog folderBrowserDialog1;
    }
}

