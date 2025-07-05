phishing/
├── deploy_phishing_infrastructure.yml *Created
├── mta_front.yml *Created
├── gophish_server.yml *Created
├── phishing_redirector.yml *Created
├── phishing_webserver.yml *Created
├── payload_redirector.yml
├── payload_server.yml
└── cleanup_phishing.yml

tasks/
├── configure_mta_front.yml *Created
├── configure_gophish_advanced.yml *Created
├── configure_phishing_redirector.yml *Created
├── configure_phishing_webserver.yml
├── configure_payload_redirector.yml
├── configure_payload_server.yml
└── setup_phishing_security.yml *Created

templates/
├── phishing/
│   ├── gophish-advanced-config.j2
│   ├── postfix-mta-front.j2
│   ├── nginx-phishing-redirector.j2
│   ├── nginx-payload-redirector.j2
│   ├── phishing-landing-page.j2
│   ├── email-templates/
│   │   ├── office365_login.j2  *Created
│   │   ├── password_expiry.j2
│   │   ├── security_alert.j2
│   │   └── file_share.j2
│   └── fedramp-compliance.j2
└── phishing_deployment_state.j2

I am looking to beef up my phishing portion of my tooland I want to make a stand alone option as well. I will be preforming both red team phishing engagements and fed ramp engagements. So the red team ones need to be more advanced and sophesticated with advanced evasion techniques etc like
SMTP smuggling aged domains MTA fronting Cloud service payload hosting CDN exploitation LOtL techniques SPF bypass methods File format manipulation
This will require more than one server
For fedramp style engagements I am not testing email security controls but only the users and I need to follow the strict guideline
 The intent is to test user compliance, not email security. Emails should be allow-listed on all security systems and be presented to the user unflagged, unmodified, and unaltered in any way. 3PAOs will provide or approve email templates and landing pages used in testing. 3PAOs must either perform this attack vector themselves, or independently evaluate the effectiveness of a third party phishing campaign. Landing pages for CSP personnel who are victims of the phishing attack should immediately identify that the email was a phish, and provide supplemental information on how to identify phishing attacks in the future. The email campaign will consist of the following: 
Email with username in body, Link to landing page, Ability to capture emails opened (hidden pixel), Landing page, Ability to tie landing page visits by user, Username and password capture, Ability to track user submission. FedRAMP requires that the 3PAO report back roles and/or metrics but not specific names. Lets keep with making this CSP agnostic as much as possible so AWS and linode can be used and other CSP as they are added to the framework. I would like everything to be as indepentent as possible so its all not running in one huge file or script and can be easily found and worked on and called to build stand alone servers or add to an existing server etc

For red team engagements I want to be able to deploy my whole red team infra or exactly what I need like just a c2, redirector, payload server, phishing server, Domain fronting server or just payload server, phishing server, Domain fronting server etc. I want an option for red team phishing which deploys

Below are deployment profiles

Profile Name: Full Red Team Infra (All the Things)

Servers:

    MTA Front | SMTP relay hides email backend

    Gophish Email Server | Phishing campaign controller (hidden)

    Phishing Redirector (CDN) | Hides phishing web server behind CDN

    Phishing Web Server | Credential capture backend

    Payload Redirector (CDN) | Hides malware delivery server behind CDN

    Payload Server | Malware hosting backend

    C2 Redirector (CDN) | Hides Havoc/Cobalt backend behind CDN

    C2 Backend | Command & control server (hidden)

Profile Name: Full Red Team Infra (No CDN Abuse)

Servers:

    MTA Front | SMTP relay hides email backend

    Gophish Email Server | Phishing campaign controller (hidden)

    Phishing Redirector (VPS) | Nginx/socat hides phishing web server

    Phishing Web Server | Credential capture backend

    Payload Redirector (VPS) | Nginx/socat hides malware delivery server

    Payload Server | Malware hosting backend

    C2 Redirector (VPS) | Nginx/socat hides C2 backend

    C2 Backend | Command & control server (hidden)

Profile Name: Phishing Infra (Credential Harvesting Only)

Servers:

    MTA Front (optional) | SMTP relay hides email backend (optional)

    Gophish Email Server | Phishing campaign controller

    Phishing Redirector (CDN or VPS) | Hides phishing web server

    Phishing Web Server | Credential capture backend

Profile Name: Phishing Infra (Credential Harvesting Only, No CDN)

Servers:

    MTA Front (optional) | SMTP relay hides email backend (optional)

    Gophish Email Server | Phishing campaign controller

    Phishing Redirector (VPS) | Nginx/socat hides phishing web server

    Phishing Web Server | Credential capture backend

Profile Name: Whitelisted Phishing Infra (User Awareness Testing)

Servers:

    Gophish Email Server | Sends phishing campaigns directly

    Phishing Web Server | Fake login or failure landing page

this needs to also set up firewall rules or security groups to ensure least privilege. I need only the MTA fronting or redirectors accessible to anyone. The main phishing server should only allow the operator to connect and then the main phishing server should be able to access the MTA, Webserver and payload server etc. We need to ensure that things are fully secure. This should be added to the main menu under the phishing server option 9 with sub menus for the different deployment options. This needs to be deployable in any provider so make as much of it provider agnositic. use existing playbooks if it make sense like security hardening etc. I also want this to have the tracker setup as well on any deployment. Make sure to consider the way the tool is built. I want minimal stuff in the deploy.py. As much as possible should be handled with tasks templates and scripts


NOTES:

- I think I need to remove all the security group stuff to the security_hardening yaml
- I dont think I need a tracker on the webserver yaml
- setup_phishing_security.yml seems redundant and AWS only focused
- 
- 