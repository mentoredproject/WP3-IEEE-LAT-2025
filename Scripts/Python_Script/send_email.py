import json
import argparse
from email.message import EmailMessage
import ssl
import smtplib

def main():
    # Parse the arguments
    args = args_parser()

    # Open the file that has the Sender email and password
    # And Receiver Email
    file = open(args.config) 
    sender_receiver = json.load(file)

    # Email Subject message
    subject = f"The experiment {args.number} is done"

    # Email Body message
    body = """
    Yahoo a new experiment is done, without error.
    """

    with open("/tmp/kube_status.txt", "r") as kube_status:
        content = kube_status.read()
        body = body + content


    em = EmailMessage()
    em['From'] = sender_receiver['sender']
    em['To'] = sender_receiver['receiver']
    em['Subject'] = subject
    em.set_content(body)

    # SSL is used to encrypt the message
    context = ssl.create_default_context()

    # send the email using the gmail smtp server
    with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
        smtp.login(sender_receiver['sender'], sender_receiver['password'])
        smtp.sendmail(sender_receiver['sender'], sender_receiver['receiver'], em.as_string())

def args_parser():
    # Inicialize the parser
    parser = argparse.ArgumentParser(
    # Program Name
    prog= 'send_email.py',
    description= 'Troughput Analysis Program',
    # End of help message
    epilog= '''
    ./send_email.py -n <experiment number> -c <json-file-with-the-information-about-sender-receiver>
    '''
    )

    # Emulation Number
    parser.add_argument('-n', '--number', required=True, help= "Number of the experiment") 


    # Informations about sender and receiver
    # Sender Email
    # Sender Password
    # Receiver Email
    parser.add_argument('-c', '--config', required=True, help= "Informations about the sender and receiver") 

    return parser.parse_args()

if __name__ == '__main__':
    main()
