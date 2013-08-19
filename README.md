Registry of (Dis)honesty
==================

The Registry of (Dis)honesty is the independent registry of certificates. It
is a part of the Eccentric Authentication Suite.

> Proving honesty

In general, you *cannot* prove honesty. You can only prove
dishonesty. What we are going to do is to set up a mechanism that will
prove dishonesty when it happens. It allows people to verify that the
site (and it's First Party Certificate Authority) have not been
dishonest so far.

> Quick introduction on eccentric authentication

We have a web site operator that runs his own certificate authority
that signs client certificate only for his own web site.  Clients can
sign up with any account name for the site. The only requirement is
that the account name is unique, no two customers of the site have the
same account name. This allows people to recognise other accounts at
the site. For example, bloggers can identify other bloggers by their
account name.

The threat is that the site owner creates 'shadow' accounts to perform
a Man-in-the-Middle attack against the bloggers.

This registry is a way to keep the site owner honest with respect to
certificate signing. When bloggers sign up, they check the
honesty-registry before sending private messages and after receiving
the first reply. 

If any blogger detects multiple certificates for a single account
name, it's a proof of protocol violation by the
site/FPCA. Whether the site owner has been dishonest or just
incompetent, is irrelevant. It's a sign that the site is not to be
trusted.

For more details, please visit: <a href="http://eccentric-authentication.org/eccentric-authentication/introduction.html">Eccentric Authentication protocol</a>.

## API

The API is a RESTlike RPC service. It has these calls: submit (certificate), check (certificate), proof (dishonesty).

### Submit

The site offers a web-form that calls this method:

    POST https://registry-of-dishonesty.example/submit

The call takes a single certificate as parameter, named
'certificate'. The service checks that it's a valid Eccentric
Authenticated certitificate. If it is valid, the service will register
the certifcate under the {sitename, CN} identity pair it finds in the
certificate. The service will reply to the caller whether it has seen
any different certificates with the same identity pair.


### Check

     GET https://registry-of-dishonesty.example/check

The call takes an identity pair {sitename, CN} and returns
all certificates with that pair it has on file. If the site has been
honest, there is just one certificate per identity pair due to the uniqueness
requirement. This call is meant to verify your own certificate at the
site or that of your communication partner. Or any other certificate you wish to check.

### Proof dishonesty

     GET https://registry-of-dishonesty.example/proof

The call takes a sitename and return all certificates that
have the same identity pair for the site. This call is meant check if
there has been any dishonesty of a site before you decide to sign up.

It should return empty for an honest site.

