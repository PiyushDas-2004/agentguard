# SSO Login

Acme Corp uses single sign-on (SSO) through Acme ID, the company identity provider. Acme ID supports SAML 2.0 and OpenID Connect, and more than 140 internal and third-party applications are connected to it, including the intranet, Ledgerly, PeopleHub and Trackwell.

Every SSO login requires multi-factor authentication. Employees approve sign-ins with a push notification in the Acme Authenticator mobile app or with a FIDO2 hardware security key. SMS codes are not accepted as a second factor. New hardware keys are requested from the IT helpdesk and arrive within 3 business days.

An SSO session lasts 12 hours. After 12 hours, or after the laptop restarts, Acme ID asks for the password and second factor again. Sessions on unmanaged devices last only 1 hour and cannot open finance or HR applications.

Applications are added to SSO by the identity team after a security review. New application requests take about 10 business days. When an employee leaves Acme, the Acme ID account is disabled within 1 hour of the termination time recorded in PeopleHub, which revokes access to every connected application at once.

SSO problems, such as a missing application tile or a failed push notification, are handled by the IT helpdesk at extension 4357.
