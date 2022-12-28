#region
// Copyright (c) 2016 Microsoft Corporation. All Rights Reserved.
// Licensed under the MIT License (MIT)
/*============================================================================
  File:     Logon.aspx.cs
  Summary:  The code-behind for a logon page that supports Forms
            Authentication in a custom security extension    
--------------------------------------------------------------------
  This file is part of Microsoft SQL Server Code Samples.
    
 This source code is intended only as a supplement to Microsoft
 Development Tools and/or on-line documentation. See these other
 materials for detailed information regarding Microsoft code 
 samples.

 THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF 
 ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO 
 THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 PARTICULAR PURPOSE.
===========================================================================*/
#endregion

using Microsoft.Samples.ReportingServices.CustomSecurity.App_LocalResources;
using System;
using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Web;
using System.Web.Security;
using System.Web.Services;

namespace Microsoft.Samples.ReportingServices.CustomSecurity
{
    public class AutoSignOn : System.Web.UI.Page
    {
        protected System.Web.UI.WebControls.Label LblUser;
        protected System.Web.UI.WebControls.TextBox TxtPwd;
        protected System.Web.UI.WebControls.TextBox TxtUser;
        protected System.Web.UI.WebControls.Button BtnRegister;
        protected System.Web.UI.WebControls.Button BtnLogon;
        protected System.Web.UI.WebControls.Label lblMessage;
        protected System.Web.UI.WebControls.Label Label1;
        protected System.Web.UI.WebControls.Label LblPwd;

        //StreamWriter streamWriter = new StreamWriter(@"C:\Nezam\PowerBiLog.txt", true);
        private void Page_Load(object sender, System.EventArgs e)
        {
            //streamWriter.WriteLine("\n\n\n" + "");
            //streamWriter.WriteLine(DateTime.Now + "    " + "**********Starts Here************");
            //streamWriter.WriteLine(HttpContext.Current.Request.Url);

            HttpRequest httpRequest = HttpContext.Current.Request;
            if (httpRequest.Headers["Authorization"] != null)
            {
                Page.Response.Write("<script>console.log('" + "Came to Authorization" + "');</script>");
                string authStr = httpRequest.Headers["Authorization"];

                if (authStr == null || authStr.Length == 0)
                {
                    return;
                }

                authStr = authStr.Trim();
                if (authStr.IndexOf("Basic", 0) != 0)
                {
                    return;
                }

                authStr = authStr.Trim();

                string encodedCredentials = authStr.Substring(6);

                byte[] decodedBytes =
                Convert.FromBase64String(encodedCredentials);
                string s = new ASCIIEncoding().GetString(decodedBytes);

                string[] userPass = s.Split(new char[] { ':' });
                string userName = userPass[0].Trim();
                string password = userPass[1].Trim();
                //streamWriter.WriteLine(DateTime.Now + "    " + "Authorization Block");
                CallLogin(userName, password);
                //streamWriter.WriteLine(DateTime.Now + "Http Request  Header Authorization" + httpRequest.Headers["Authorization"]);
                //streamWriter.WriteLine(DateTime.Now + "  Server 1" + Server.MapPath(""));
                //streamWriter.WriteLine(DateTime.Now + "    " + "Ends here");
                //streamWriter.Close();                
            }
            else if (HttpContext.Current.Request.Url.ToString().IndexOf("username") != -1)
            {
                string userid = "";

                String currurl = Server.UrlDecode(HttpContext.Current.Request.Url.ToString());

                // Parse the query string variables into a NameValueCollection.
                NameValueCollection qscoll = HttpUtility.ParseQueryString(currurl);

                foreach (String s in qscoll.AllKeys)
                {
                    string s1 = qscoll[s];
                    string[] s2 = s1.Split('&');
                    foreach (string st in s2)
                    {
                        //streamWriter.WriteLine(DateTime.Now + " XX QueryString" + st);
                        if (st.IndexOf("username") != -1)
                        {
                            //streamWriter.WriteLine(DateTime.Now + " UserName QueryString" + st);
                            userid = st.Split('=')[1];
                        }
                    }
                }
                FormsAuthentication.RedirectFromLoginPage(userid, true);
                //streamWriter.Close();
            }
        }

        [WebMethod]
        public void CallLogin(string user, string pwd)
        {
            user = user.Trim();
            pwd = pwd.Trim();
            bool passwordVerified = false;
            //StreamWriter streamWriter = new StreamWriter(@"C:\Nezam\PowerBiLog.txt", true);
            try
            {
                //streamWriter.WriteLine(DateTime.Now + "    " + user + pwd);
                byte[] bytes = Encoding.ASCII.GetBytes(user);
                string usersomeString = Encoding.ASCII.GetString(bytes);
                //streamWriter.WriteLine(usersomeString);
                byte[] pwdbytes = Encoding.ASCII.GetBytes(pwd);
                string pwdsomeString = Encoding.ASCII.GetString(pwdbytes);
                //streamWriter.WriteLine(pwd);
                //streamWriter.WriteLine(DateTime.Now + "    " + user + pwd);
                //streamWriter.WriteLine(DateTime.Now + "    " + "Call Login");
                passwordVerified = AuthenticationUtilities.VerifyPassword(usersomeString, pwd);

                //FormsAuthentication.EnableCrossAppRedirects = true;
                //streamWriter.WriteLine(DateTime.Now + "    " + "Password Verified " + passwordVerified);
                if (passwordVerified)
                {
                    //FormsAuthentication.RedirectFromLoginPage(user, true);                                   
                }
                else
                {
                    //streamWriter.WriteLine(DateTime.Now + "    " + "Invalid password" + passwordVerified);
                    Response.Redirect("AuthenticationFailed.aspx");
                }
                //streamWriter.WriteLine(DateTime.Now + "    " + "passwordVerified" + passwordVerified);

                if (passwordVerified == true)
                {
                    // The user is authenticated
                    // At this point, an authentication ticket is normally created
                    // This can subsequently be used to generate a GenericPrincipal
                    // object for .NET authorization purposes
                    // For details, see "How To: Use Forms authentication with 
                    // GenericPrincipal objects
                    lblMessage.Text = string.Format(CultureInfo.InvariantCulture,
                       Logon_aspx.LoginSuccess);
                    BtnRegister.Enabled = false;
                    //FormsAuthentication.RedirectFromLoginPage(user, true);                   
                    //streamWriter.WriteLine(DateTime.Now + "    " + "RedirectFromLoginPage" + lblMessage.Text);
                }
                else
                {
                    lblMessage.Text = string.Format(CultureInfo.InvariantCulture,
                      Logon_aspx.InvalidUsernamePassword);
                    //streamWriter.WriteLine(DateTime.Now + "    " + "Invalid password" + passwordVerified);
                }
            }
            catch (Exception ex)
            {
                //streamWriter.WriteLine(DateTime.Now + "    " + "Catch" + ex.Message);
                lblMessage.Text = string.Format(CultureInfo.InvariantCulture, ex.Message);
                return;
            }
            finally
            {
                //streamWriter.WriteLine(DateTime.Now + "    " + "Finally " + lblMessage.Text);
                //streamWriter.WriteLine(DateTime.Now + "    " + "*****************Ends Here***************");

            }

        }

        #region Web Form Designer generated code
        override protected void OnInit(EventArgs e)
        {
            InitializeComponent();
            base.OnInit(e);
        }

        private void InitializeComponent()
        {
            this.BtnLogon.Click += new System.EventHandler(this.ServerBtnLogon_Click);
            this.BtnRegister.Click += new System.EventHandler(this.BtnRegister_Click);
            this.Load += new System.EventHandler(this.Page_Load);

        }
        #endregion

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void BtnRegister_Click(object sender,
          System.EventArgs e)
        {
            string salt = AuthenticationUtilities.CreateSalt(5);
            string passwordHash =
               AuthenticationUtilities.CreatePasswordHash(TxtPwd.Text, salt);
            if (AuthenticationUtilities.ValidateUserName(TxtUser.Text))
            {
                try
                {
                    AuthenticationUtilities.StoreAccountDetails(
                       TxtUser.Text, passwordHash, salt);
                }
                catch (Exception ex)
                {
                    lblMessage.Text = string.Format(CultureInfo.InvariantCulture, ex.Message);
                }
            }
            else
            {

                lblMessage.Text = string.Format(CultureInfo.InvariantCulture,
                    Logon_aspx.UserNameError);
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1031:DoNotCatchGeneralExceptionTypes")]
        private void ServerBtnLogon_Click(object sender,
          System.EventArgs e)
        {
            bool passwordVerified = false;
            try
            {
                passwordVerified =
                   AuthenticationUtilities.VerifyPassword(TxtUser.Text, TxtPwd.Text);
                if (passwordVerified)
                {
                    FormsAuthentication.RedirectFromLoginPage(
                       TxtUser.Text, false);
                }
                else
                {
                    Response.Redirect("logon.aspx");
                }
            }
            catch (Exception ex)
            {
                lblMessage.Text = string.Format(CultureInfo.InvariantCulture, ex.Message);
                return;
            }
            if (passwordVerified == true)
            {
                // The user is authenticated
                // At this point, an authentication ticket is normally created
                // This can subsequently be used to generate a GenericPrincipal
                // object for .NET authorization purposes
                // For details, see "How To: Use Forms authentication with 
                // GenericPrincipal objects
                lblMessage.Text = string.Format(CultureInfo.InvariantCulture,
                   Logon_aspx.LoginSuccess);
                BtnRegister.Enabled = false;
            }
            else
            {
                lblMessage.Text = string.Format(CultureInfo.InvariantCulture,
                  Logon_aspx.InvalidUsernamePassword);
            }
        }
    }
}
