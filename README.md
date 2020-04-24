# CFAccess

Cloudflare Access for MODX CMS.

## What does it do?

Lock specific Resources, Contexts, or entire MODX sites behind [Cloudflare Access](https://www.cloudflare.com/en-ca/products/cloudflare-access/). More specifically, this Extra validates the JWT token sent with the Cloudflare Authoriztion cookie, and optionally assigns a MODX User to the session if a match is found.

## Why?

Once you've [secured your web server and set up Cloudflare Access](https://sepiariver.com/modx/protect-your-web-server-with-cloudflare-access/), this Extra provides "extra" functionality that isn't _required_ but supports the following use cases.

1. You want the extra layer of security that comes with validating the JWT sent by Cloudflare's proxies. You can do it on every web page initialization with the Plugin, or only specific Resources with the Snippet.
2. You want access to the decoded JWT, which includes the user's email.
3. You want to match the user's email to a MODX User to display personalized content, collect information, or any of the other things you could do in MODX with a User.
4. You want to apply more granular permissions, which MODX supports out of the box, like Resource Groups, Context permissions, etc.

### Considerations

CFAccess does **not** call `addSessionContext`, do anything with sessions, nor set any cookies. Rather, it assigns the `$modx->user` object for the _current request_. The JWT is validated on every request, for which the Plugin or Snippet is configured to execute.

Both the Snippet and Plugin execute in front-end Contexts. CFAccess does not support logging Users in to the `mgr`. 

CFAccess does not create MODX Users. If you need more advanced user management with a single sign-on solution, check out [Auth0 for MODX](https://sepiariver.com/modx/auth0-for-modx-cms/).

## Setup

### Secure Your Origin Server

There are a [variety of ways to do this](https://sepiariver.com/modx/protect-your-web-server-with-cloudflare-access/). Probably one of the easiest methods that have a suitably secure outcome, is the combination of a Cloudflare Worker and some web server configuration. It shouldn't take more than 10-20 minutes, although it's highly recommended to deploy it in a test or dev environment, prior to putting it into production.

**TL;DR**

Script a Cloudflare Worker to send a secret key in a custom header. Only the Cloudflare proxy servers will be able to do this, as long as your secret key remains secret. On your web server, do something like:

```
if ($http_x_my_custom_header != MyCryptographicallyRandomGeneratedKey) {
    return 407; 
}
```

for nginx. [Remember, if is evil, except in specific cases](https://www.nginx.com/resources/wiki/start/topics/depth/ifisevil/). On Apache, use the [Require directive](https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html#require):

```
Require expr %{HTTP:X-My-Custom-Header} = 'MyCryptographicallyRandomGeneratedKey'
```

A more detailed guide can be found [in this blog post](https://sepiariver.com/modx/protect-your-web-server-with-cloudflare-access/).

### Cloudflare Access Setup

Securing the origin means that only Cloudflare proxy servers can make requests, but no access controls have been put in place yet. In the Cloudflare Dashboard, select the domain/zone for which you'd like to enable Access. Navigate to the Access configuration page. Follow the instructions to configure your Login Domain and identity provider(s). The default One-Time Pin method is convenient.

> Note: keep a copy of your Login Domain—you'll need it when you set up the CFAccess MODX Extra in your site.

Click the "Create Access Policy" button to create a new policy. You can optionally scope the policy to a subdomain or path. You can add users or user groups based on email, email domain, or IP address. Make a note of the Application Audience (AUD) Tag. This is also required to configure the CFAccess Extra.

### CFAccess Extra Settings

#### System Settings

All setting keys are prefixed with the namespace `cfaccess.` so `auth_aud` refers to the installed System Setting `cfaccess.auth_aud`. The included Snippet and Plugin use the System Settings only, and will not allow cascading settings from the Context, User Group, nor User—for added security. Generally speaking, permissions in the MODX Manager to edit System Settings, Context Settings, User Group Settings, User Settings, and any executable Elements including Plugins and Snippets, should only be granted to users with the highest level of trust. (Also in Revo versions prior to 3.x the permission to edit TVs—not TV values but the TV objects themselves—also endows broad capabilities.)

- `auth_aud` The Application Audience (AUD) Tag from you Cloudflare Access Policy.
- `auth_url` The URL formed from the scheme, Login Domain configured in your Cloudflare Dashboard, and trailing slash:  `https://example.cloudflareaccess.com/`
- `contexts` Comma-separated list of Context keys. When the CFA Authenticate Plugin executes in one of these Contexts, it will validate the JWT in the `CF_Authorization` cookie and behave accordingly. The special value `cfaccess_all_contexts` will trigger JWT validation on all Contexts. An empty value bypasses JWT checking, so the Plugin will essentially be disabled.
- `require_moduser` If enabled, the CFAccess will consider the JWT _invalid_ unless the email from the JWT payload matches either a username or email of an existing MODX User. **NOTE: it does not do any permissions checks on the MODX User, nor does it even check if the User is active or blocked. If you need these types of checks you can use the `assign_moduser` property.**
- `assign_moduser` If enabled, CFAccess will attempt to assign the MODX User (`modUser`) that has a username or email that matches the one from the validated JWT payload, as the _current_ MODX User. MODX will then apply that User's permissions and user data to the current request. This is helpful if you have MODX ACLs configured and want the authenticated User to be subject to those. **Tread carefully here, because the combination of MODX ACLs and the assignment of a User may lead to unintended results.**
- `debug` Instantiates the CFAccess class in debug mode, which in turn sets `modX::LOG_LEVEL_ERROR`.

## Usage

### Snippet: cfa.Authenticate

Validates the `CF_Authorization` JWT token and produces various outcomes based on configured `$scriptProperties`:

- `authenticatedTpl` (string) Name of Chunk to use as a display template for authenticated requests. Chunk is passed the `$scriptProperties` and the `decoded_email` from the JWT.
- `unauthenticatedTpl` (string) Name of Chunk to use as a display template for UNauthenticated requests. Irrelevant unless `overrideAuthorizationRedirect` is enabled. No properties are passed to this Chunk.
- `overrideAuthorizationRedirect` (bool) USE WITH CAUTION: rather than sending a 4xx response to unauthenticated requests, the Chunk named in the `unauthenticatedTpl` property will be displayed. This doesn't actually protect the Resource on which the Snippet is called, but only shows different content.
- `obfuscate` (bool) Obfuscate unauthenticated requests with a 404 response rather than 401.
- `runSnippetsOnAuth` (string) Comma-separated list of Snippet names. On successful authentication, the Snippets will be executed in the order specified. Members of the `$scriptProperties` array that are prefixed with the supplied Snippet name, and a `_` as delimiter, are passed to the Snippet being executed. Results are returned in the `authorizedTpl` in placeholders of the same name as the executed Snippets. Results are **not** passed from Snippet to Snippet—only the properties from `cfa.Authenticate`.

#### Examples

```
[[!cfa.Authenticate? 
    &authenticatedTpl=`authed` 
    &obfuscate=`0` 
    &runSnippetsOnAuth=`foo, bar, notify` 
    &foo_test=`footest`
    &bar_test=`bartest`]]
```

In the Chunk named "authed":

```
Foo: [[+foo]]
Bar: [[+bar]]
Notification: [[+notify]]
```

`foo` and `bar` Snippets both contain:

```
return $modx->getOption('test', $scriptProperties, '');
```

`notify` Snippet:

```
$email = $modx->getOption('decoded_email', $scriptProperties, '');
if (!empty($email)) {
    // Send email
    return 'Email has been sent';
}
```

Output will be:

```
Foo: footest
Bar: bartest
Notification: Email has been sent
```

### Plugin: CFA Authenticate

Validates the `CF_Authorization` JWT token and sends a 4xx response based on the `$scriptProperties`:
- `obfuscate` (bool) Obfuscate unauthenticated requests with a 404 response rather than 401.

If the Plugin Event is fired on the initialization of a Resource (`OnWebPageInit`) in a Context with its key in the `cfaccess.contexts` System Setting, the Plugin will validate the JWT in the `CF_Authorization` cookie, and optionally invoke the functionality controlled by `cfaccess.require_moduser` and `cfaccess.assign_moduser`. See the "System Settings" section above for more details.

## Tests

`phpunit` tests in [tests/](tests/) folder.