import win32com.client
import os

def send_outlook_email(recipient, cc, subject, body_html, attachment_path=None):
    outlook = win32com.client.Dispatch("Outlook.Application")
    mail = outlook.CreateItem(0)  
    mail.To = recipient 
    mail.CC = cc  
    mail.Subject = subject  
    mail.HTMLBody = body_html  

    # Attach file if provided
    if attachment_path:
        mail.Attachments.Add(attachment_path)

    mail.Send()  # Send the email
    print("Email sent successfully!")


# recipient_email = "bharathj0410@outlook.com"
# cc_email = ""
# subject = "Test Email with CC, Attachment & HTML"
# html_body = ""
# attachment = os.path.abspath("AbuseIPDB_Result.xlsx")

# send_outlook_email(recipient_email, cc_email, subject, html_body, attachment)
