:tocdepth: 1

.. sectnum::

Abstract
========

The current design for authentication for the Rubin Science Platform leaks cookies and user tokens to backend services.
This undermines isolation between services, which could become relevant if a service is compromised.
This document proposes several possible alternative designs, including one that uses separate hostnames for each Rubin Science Platform service, and discusses the complexity and effort trade-offs.

See `DMTN-193`_ for a more general discussion of web security for the Science Platform.

.. _DMTN-193: https://dmtn-193.lsst.io/

Background
==========

The Rubin Science Platform is, for the purposes of this document, a set of web services used by both web browsers and non-browser clients.
Browser clients authenticate with an encrypted session cookie.
Other clients authenticate with an ``Authorization`` header containing either a bearer token or an HTTP Basic Authentication string.

Authentication in a browser is done via either OpenID Connect or OAuth 2 to an external authentication provider.
Successful authentication then sets a session cookie in the browser, which is used to authenticate subsequent requests until that cookie expires.
Rather than asking each application to verify that authentication cookie, the authentication verification is provided by a central service.
That service, Gafaelfawr, can be invoked in one of two ways: using OpenID Connect if the protected application supports it natively, or by using an NGINX ``auth_request`` handler and configuration on the ingress of the application.
The ``auth_request`` handler approach is preferred for most Science Platform services.

When an ``auth_request`` handler is used, the NGINX ingress for the Rubin Science Platform instance makes a subrequest to Gafaelfawr that includes the headers of the original browser request to the service URL.
Gafaelfawr then locates the cookie, decrypts it, verifies the authentication credentials in that cookie, and (if successful) returns the results of that authentication verification in reply headers.
NGINX then can be configured to include those reply headers as request headers in the proxied request to the protected application, which can then extract authentication information from those trusted headers.

Currently, a given deployment of the Rubin Science Platform uses a single hostname for all components.
Different services are mounted on different routes under that hostname.
For example, for a Rubin Science Platform deployment at ``https://data.lsst.cloud``, the Notebook Aspect is at ``https://data.lsst.cloud/nb``, the Portal Aspect is at ``https://data.lsst.cloud/portal``, and so forth.
(`DMTN-076`_, not yet published, will propose a longer-term URL scheme for the Science Platform components.)

.. _DMTN-076: https://dmtn-076.lsst.io/

In general, all services running on the Rubin Science Platform are trusted.
In some cases, such as the Notebook Aspect, the running notebook is always given an authentication token with most of the permissions as the user's session cookie.
However, ideally, services should be as isolated from each other as is feasible, and should only be able to make the calls to other services that are explicitly permitted by authorization policies, following a principle of least privilege.

Problem statement
=================

The ``auth_request`` handler approach supplements the request headers but does not remove headers.
Specifically, it does not remove any cookies the browser sends (nor can it drop all cookies, since protected applications may use their own cookies).
Therefore, the authentication cookie used by Gafaelfawr to verify the user's authentication is also sent to the protected service in the HTTP headers.

The authentication cookie itself is encrypted with a key known only to Gafaelfawr, so no other component can extract the underlying authentication token and use it in a different context.
However, the entire encrypted cookie acts as a bearer token and can itself be used to authenticate requests.
That cookie is scoped to the hostname of the Rubin Science Platform deployment.
Therefore, any service with a registered HTTP ingress in the Rubin Science Platform, whether or not it is protected by an ``auth_request`` handler and including services that instead use OpenID Connect, receives a copy of the authentication cookie used by Gafaelfawr.
If that service is compromised, the attacker can obtain that cookie from the incoming request and use it to make browser requests to other services in the same Science Platform deployment with the credentials of the user.
This includes requests to the Gafaelfawr authentication service itself to, for instance, create new, persistent authentication tokens for that user that would be under the control of the attacker.

A related but slightly different problem is that, since all Rubin Science Platform services are running under the same hostname, they all share the same JavaScript trust domain.
This means that a compromise of the web interface of any service (via XSS, for example) would allow an attacker to make authenticated requests to all other Rubin Science Platform services as the user.
This has the same effect as stealing the user's authentication cookie but may be easier to accomplish.

JupyterHub recommends `enabling subdomains <https://jupyterhub.readthedocs.io/en/stable/reference/websecurity.html>`__ so that each user's notebook is hosted in a unique subdomain for exactly this reason.

The implication is that internal authorization controls between the Rubin Science Platform components are only fully effective if an attacker cannot gain access to the raw headers of a request to one of the components and cannot inject JavaScript into the web interface.

Note that even if an attacker gains that access, they can only misuse credentials that are sent to the service while they have compromised that service.
They cannot make requests as arbitrary users who have not accessed the compromised service.
However, a patient attacker could wait until a user with administrative permissions accesses the compromised service and then leverage their credentials to impersonate arbitrary users.

The same problem exists for non-browser authentication using the ``Authorization`` header.
That header is also sent to the protected service after it is interpreted by the ``auth_request`` handler.

Alternative designs
===================

The following alternative designs would avoid exposing authentication credentials to protected services that could be used to access other protected services.

Replace ``Cookie`` and ``Authorization`` headers
------------------------------------------------

While the ``auth_request`` handler cannot remove headers, NGINX and the Kubernetes ``Ingress`` annotations do provide a way of replacing headers in the request with headers returned by the ``auth_request`` handler before passing them to the backend.
We could make use of this by having Gafaelfawr return a ``Cookie`` header that is the same as the incoming request but with the Gafaelfawr cookie stripped out of it, and then configure the ingress to replace the incoming header with that header via:

.. code-block:: yaml

   nginx.ingress.kubernetes.io/auth-response-headers: Cookie

(plus any additional headers from Gafaelfawr that the protected application uses).
A simpler approach would work for the ``Authorization`` header: listing the header in ``auth-response-headers`` without sending that header in the ``auth_request`` handler response should strip the header from the request before sending it to the backend service.
This would only work for services that do not reuse the ``Authorization`` header for their own purposes (JupyterHub does this).

For backend services that must receive a token in the ``Authorization`` header (CADC's TAP service is currently in this category), Gafaelfawr could be configured to return a delegated token in the ``Authorization`` header.

Advantages:

- Works transparently with the current Rubin Science Platform design, with no changes required to protected services, routes, or hostnames.
- Addresses both the cookie and ``Authorization`` header cases.
- Conceptually simple, and collects all of our request manipulation code in the same place (the Gafaelfawr ``auth_request`` handler).

Disadvantages:

- Requires parsing and surgery on the ``Cookie`` header in Gafaelfawr, which opens the possibility of unexpected browser interactions or problems with invalid but still working headers.
- Only protects against token leakage to authenticated URLs that are protected by Gafaelfawr.
  Requests that do not go through an ``auth_request`` handler will still leak cookies and ``Authorization`` headers.
  This includes any request to a backend service that uses Gafaelfawr's OpenID Connect support instead.
  This could be mitigated by supporting a stripped-down ``auth_request`` handler mode that only cleans the headers and sending all requests, even unauthenticated requests, through an ``auth_request`` handler, at the cost of additional complexity and possible fragility.
- This adds additional complexity to the required ingress configuration to use Gafaelfawr, which is already very complex.
  If we take this approach, it may be worth adding Gafaelfawr support for a custom ingress resource and have Gafaelfawr add the appropriate annotations and generate the real ``Ingress`` resource from that custom resource.
- Does not isolate the JavaScript of each service.
  All services are still in the same JavaScript origin, which means that malicious JavaScript injected into any service could still make authenticated requests to other services, even though the attacker would not have direct access to the cookie.

Strip Gafaelfawr cookie from proxied request
--------------------------------------------

It may be possible to add NGINX configuration to remove the cookie from the proxied request.
It would still be present in the ``auth_request`` subrequest, but would not be sent to the destination host.
See, for example, these instructions to `remove a specific cookie with NGINX <https://librenepal.com/article/remove-specific-cookies-with-nginx/>`__, which use the following snippet::

  set $new_cookie $http_cookie;
  if ($http_cookie ~ "(.*)(?:^|;)\s*some_cookie=[^;]+(.*)") {
    set $new_cookie $1$2;
  }
  proxy_set_header Cookie $new_cookie;

A simpler approach also works for the ``Authorization`` header::

  proxy_set_header Authorization "";

However, the Notebook Aspect also uses the ``Authorization`` header for its own internal purposes, so the logic may need to be more complex, or the Notebook Aspect may need to be excluded.

Advantages:

- Works transparently with the current Rubin Science Platform design, with no changes required to protected services, routes, or hostnames.
- Addresses both the cookie and ``Authorization`` header cases.

Disadvantages:

- Does not isolate the JavaScript of each service.
  All services are still in the same JavaScript origin, which means that malicious JavaScript injected into any service could still make authenticated requests to other services, even though the attacker would not have direct access to the cookie.
- It's not clear how this stacks with ``auth_request`` subrequests, which are also done with proxying.
  The cookie and ``Authorization`` header must be included in that request.
  Some experimentation to find the right configuration may be required.
- Editing a structured field with regular expression matching is error-prone and potentially fragile.
  There is at least one report that NGINX then escaped the header and broke other cookies, and other problems like that are possible.
- This relatively complex NGINX configuration would need to be added to every ingress definition used in the Rubin Science Platform and kept up-to-date if it needed to change.
- Given the complex interactions between proxying, ``auth_request``, and regex matching, this is the type of configuration that runs a risk of breaking with NGINX upgrades.

Use separate per-host cookies for each application
--------------------------------------------------

If each protected service had its own authentication session cookie that was only usable by that service, and only that cookie was sent to requests for that service, that would eliminate the problem.

This could be done as follows:

- Create a separate hostname for each service.
  In other words, for the Rubin Science Platform instance hosted at ``data.lsst.cloud``, the Notebook Aspect would be at ``nb.data.lsst.cloud`` (and ``username.nb.data.lsst.cloud`` once a notebook has been launched), the Portal Aspect would be at ``portal.data.lsst.cloud``, and so forth.
  The authentication system itself would use ``auth.data.lsst.cloud``.
  (Per-service granularity is ideal from a security standpoint, but this approach works with any granularity of hostnames.
  We could instead group services into a small number of security domains and accept attacker movement within a security domain.
  The most important to separate are, first, the authentication system and the notebooks, and then, second, the Portal Aspect.
  API services could probably be grouped into one hostname without much loss of security provided that the ``Authorization`` header is stripped.)
- The authentication session cookie for each of those services would be scoped to only that hostname and would use the ``__Host-`` prefix.
  See the `Set-Cookie documentation <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie>`__ for more information about that prefix.
- The cookie, encrypted in a key known only to Gafaelfawr, would contain the hostname for which the cookie was valid.
  Gafaelfawr would not honor the cookie as authentication to any other domain.
  This would prevent authenticating to one service with a cookie stole from a request to a different service.

This means there would no longer be a single authentication cookie for the entire Rubin Science Platform instance.
That, in turn, means that authentication to a given protected service through a web browser would become somewhat more complicated.
Rather than simply redirecting to ``/login`` and then back to the protected service once the cookie has been set, each protected service would have to follow a login protocol similar to OAuth 2.
This could still be implemented in the ``auth_request`` handler.

The similar but more difficult problem of authenticating web services at arbitrary hostnames using OAuth 2 is handled as follows:

#. Service sets a cookie containing a random state string.
   (The state string is required to prevent `session fixation <https://owasp.org/www-community/attacks/Session_fixation>`__.)
#. Unauthenticated user is redirected to the identity provider, including the state string in the request.
#. The identity provider authenticates the user.
#. The identity provider redirects the user back to the protected service, including the state string and an authentication code in the request.
#. The protected service compares the state strings and ensures they match.
#. The protected service presents the code to the identity provider, which returns authentication information about the user.
#. The protected service creates a session cookie containing that now-verified authentication information.

In this case, since the same software component can act as both the protected service and the identity provider, step 6 can be simplified by using shared state.
The login protocol would instead look like this:

#. Service creates an encrypted cookie for its hostname containing a random state string.
#. Service redirects the user to the ``/login`` route on the separate ``auth`` hostname for this Rubin Science Platform deployment and includes the state string and the return URL in that request.
#. The ``/login`` route authenticates the user.
   This may redirect to another provider, or may be immediate if the user has already authenticated to some other service.
   Store the user's authentication credentials in a cookie specific to the ``auth`` hostname to fulfill subsequent authentication requests.
   Create a random Redis key.
   In Redis, under that key, store the domain authenticated, the state string, and the user's credentials.
#. Redirect the user back to a designated reserved URL on the same hostname as the return URL.
   Include the new Redis key (which acts as an authentication code) in that request.
   Unfortunately, the authentication system has to pass state back to the hostname of the protected service, so this intermediate URL is needed.
#. Using the ``auth_request`` handler, intercept that request.
   Retrieve the information from the Redis key.
   Verify that the state and hostname match.
   Delete the Redis key.
   Set a cookie containing the hostname and authentication credentials from the Redis data, which will act as the authentication session cookie for that hostname going forward.
#. Redirect the user back to the URL they were trying to visit.
   The user now has a cookie for that hostname whose internal (encrypted) data matches the hostname of the request, and authentication can proceed as normal.

This is the same process as OAuth 2 but without step 6 because external storage is used to retrieve the information instead.

Advantages:

- Also provides protection against malicious JavaScript hosted by one Rubin Science Platform service by separating services into different JavaScript origins.
  Currently, all services are the same origin for JavaScript purposes, so malicious JavaScript hosted by any service can fool the browser into making authenticated requests to other services on behalf of the attacker.
  Separating the services into different origins would bring the normal JavaScript cross-origin request policy into play, which would provide substantial protection against lateral movement between services using JavaScript (via CSRF, for example).
- Separates the session cookies into separate cookies for each hostname that only work for that hostname.
- Uses well-understood cookie properties and parallels the well-tested OAuth 2 authentication flow.
- Doesn't require any special NGINX configuration.

Disadvantages:

- Requires some significant changes to the authentication system to implement this new authentication flow.
- Adds additional complexity to each internal authentication request (akin to using OpenID Connect internally).
- Does not address the ``Authorization`` header problem, since we cannot ask users to use per-service tokens.
  However, it may be possible to use a combination of this approach and either ``auth_request`` handler stripping or NGINX configuration to hide the ``Authorization`` header from protected services.

Use path-restricted cookies
---------------------------

Theoretically, a variation of the previous design can be done with path-restricted cookies instead.
This would allow all protected services to use the same hostname, but maintain separate cookies for each protected service.
Rather than issuing the cookies to different hostnames, the cookies would use a path restriction, limiting the cookie to only the route prefix used by that application.

The rest of the design would be identical to using per-host cookies except the cookies could not use the ``__Host-`` prefix (since it forbids path-restricted cookies).

In practice, path-restricted cookies provide little security benefit because they are stricter than the same-origin policy of JavaScript and thus can be bypassed by using malicious JavaScript.

This approach would have all of the disadvantages of per-host cookies without the benefit of site isolation against malicious JavaScript.
The only advantage would be to avoid needing to create and expose separate hostnames per service, which is not a sufficiently compelling advantage.

Discussion
==========

The best solution from a security standpoint would be to use per-host cookies plus ``auth_request`` header stripping to remove the Gafaelfawr cookie and suppress the ``Authorization`` header.
This achieves defense in depth by not leaking authentication crendentials to services that do not need them while also limiting the scope of those credentials.
Using both mechanisms would relieve some pressure on creating separate origins for every service and would make it safer to group some services together on the same origin for the sake of simplicity, as long as at least the authentication system and the notebooks were moved to different origins.

This approach would require reasonably substantial development effort in the authentication system to add the more complex login flow for each origin.
This work should be coupled with enabling per-user notebook URLs for JupyterHub.

It's not clear how important fixing this issue is relative to other security work that we could be doing.
The boundaries between services inside the Rubin Science Platform are not that strong, by design.
For example, a spawned server in the Notebook Aspect, by design, should be able to make any API call to any other service on behalf of the user except for the authentication service itself.
The benefits of isolating the services from each other are only significant if effort is also invested into defining scopes for tokens, setting authorization rules on services, and restricting the scopes of internal tokens issued to services.
Very little of that work has yet been done.
Protecting the external attack surface and basic authentication flow of the Rubin Science Platform is currently a higher priority.

That said, isolating services from each other to make lateral movement by an attacker more difficult is a long-term security goal.
It's always preferable to apply principle of least privilege where possible.
Service isolation (and particularly JavaScript isolation gained by the per-host cookie approach and separate hostnames for each protected service) would provide additional peace of mind when deploying third-party services with possibly poor security practices into the Rubin Science Platform.
Requests for such services seem likely over the full course of the project.

Implementing per-host cookies would let us choose the granularity of security domain that we want.
For example, we could group all the core Rubin-written services other than the Notebook Aspect and the Portal Aspect on one hostname and put ancillary services on a different hostname, thus gaining protection against an attacker moving between those two security domains (but not within them).

Recommendations
===============

#. Do nothing for the launch of the Intermediate Data Facility.
   Live with this problem for now.
#. Add support for stripping cookies from the ``Cookie`` header and stripping or replacing the ``Authorization`` header to Gafaelfawr.
   This is relateively simple and already adds a lot of security benefit, although it doesn't protect against leakage on unauthenticated routes.
#. Prioritize the user registration and external authentication flow and basic Kubernetes security until the risks in those areas are well-understood and reasonably mitigated.
#. Implement support for the more complex login flow required for per-host service deployment once the user registration and external authentication flow work is complete.
#. Plan on using more granular hostnames when deploying the Rubin Science Platform on the US Data Facility.
   At the least, separate core Rubin Science Platform services from ancillary services that may be less secure or easier to attack.
