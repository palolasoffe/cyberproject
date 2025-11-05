LINK: https://github.com/palolasoffe/cyberproject/
Installation instructions: basic Django-project instructions

The flaws 1, 2, 3 and 5 are from OWASP top ten list, 2017 version. Flaw 4 is CSRF.

FLAW 1:
Link to flaw 1: https://github.com/palolasoffe/cyberproject/blob/main/projectsite/polls/views.py - lines 25-37
Description of flaw 1:
Cross-Site Scripting (XSS) is a vulnerability that allows malicious actors to inject client-side scripts into websites. In my project the search view reads a query parameter (q = request.GET.get('q', '')) and the corresponding template renders it with the |safe filter. By using |safe Django’s auto-escaping is diasbled and the site will render raw HTML/JS from user input into the page. An attacker can provide a payload such as:
/polls/search/?q=<script>alert('XSS')</script>
which will execute in the victim’s browser.
How to fix it:
Remove the |safe filter in the template polls/search.html and rely on Django’s automatic escaping. The project itself already contains the FIX commented out in both files views.py and polls/search.html. By removing the |safe filter from the template polls/search.html Django's built-in auto-escaping is enabled. Replace the line:
<p><strong>Search query:</strong> {{ q|safe }}</p>
With:
<p><strong>Search query:</strong> {{ q }}</p>

FLAW 2:
Link to flaw 2: https://github.com/palolasoffe/cyberproject/blob/main/projectsite/polls/views.py - lines 40-67
Description of flaw 2:
Broken Authentication. The login view demonstrates two issues:
1.	Hardcoded/demo credentials allowed: if user is not None or (username == 'demo' and password == 'demo') this bypasses proper authentication.
2.	Manual session handling: the view stores request.session['user'] = username instead of properly using Django’s login() function to set the authenticated user and session securely.
3.	Also superuser has weak credentials as username = admin and password = admin. These username and password are very easy to assume.
These issues permit attackers to bypass authentication and create inconsistent session states. The hardcoded credential is an obvious backdoor, because it can be inspected from the website’s source code.
How to fix it:
Use Django's authentication API correctly. The commented-out secure code (lines 55-61) demonstrates the correct way:
user = authenticate(request, username=username, password=password)
if user is not None:
    login(request, user)
    return HttpResponseRedirect(reverse('polls:login_successful'))
else:
    message = 'Invalid credentials'
Remove the hardcoded demo account and do not manipulate request.session manually for login state. Ensure the view imports the login helper correctly and that LOGIN_URL and session settings are properly configured. By replacing the code in lines 62-67 with the lines 56-61 the hardcoded credentials are disabled, and the authentication is only based on registered users. Only use strong password for superuser.

FLAW 3:
Link to flaw 3: https://github.com/palolasoffe/cyberproject/blob/main/projectsite/polls/views.py  - lines 73-88
Description of flaw 3:
Sensitive Data Exposure means that attackers may steal or modify weakly protected data to conduct crimes. In this site the leak_secret view returns the application secret key in plain text, without encryption. These lines in the code allow attackers to get sensitive information unprotected:
secret = getattr(settings, 'SECRET_KEY', 'no-secret')
return HttpResponse(f"Leaked secret: {secret}")
Exposing SECRET_KEY (or any sensitive setting) to unauthenticated users can allow attackers to craft valid sessions, forge cookies, and break other cryptographic protections.
How to fix it:
Never expose secret material through a web endpoint. The file includes comment suggesting to remove the vulnerable code and return a benign message.
Replace the lines:
secret = getattr(settings, 'SECRET_KEY', 'no-secret')
    return HttpResponse(f"Leaked secret: {secret}")
With (displayed text is an example):
return HttpResponse('No secret information here :(')
Also ensure SECRET_KEY is not hard-coded in version control (see FLAW 5). Keep secrets in environment variables or a secure secret store.

FLAW 4:
Link to flaw 4: https://github.com/palolasoffe/cyberproject/blob/main/projectsite/polls/views.py - lines 106-118
Description of flaw 4:
Cross-Site Request Forgery (CSRF) allows an attacker to send unauthorized requests to a web application from another site. The report view has been decorated with @csrf_exempt (disabling Django’s CSRF protection). That allows a remote attacker to submit forms on behalf of an authenticated user by luring them to a malicious page that auto-submits a form to /polls/report/.
How to fix it:
Remove @csrf_exempt from the view and add {% csrf_token %} inside the <form> in report.html -template. The comments in the code already state:
Remove the @csrf_exempt decorator above the function report in views.py
Add {% csrf_token %} inside the <form> tag in report.html

FLAW 5:
https://github.com/palolasoffe/cyberproject/blob/main/projectsite/projectsite/settings.py - lines 22-41
Description of flaw 5:
Security Misconfiguration happens when a system or application isn’t set up securely. This can include things like using default passwords, leaving unnecessary features enabled, showing too much error information, or failing to update software. There are a few issues in the configurations: hardcoded SECRET_KEY in source code / version control, mis-set DEBUG in production, and permissive/empty ALLOWED_HOSTS. Hardcoded SECRET_KEY allows anyone to inspect it by viewing source code. DEBUG = True in production exposes error pages with stack traces, settings, and database queries to attackers. ALLOWED_HOSTS = [] accepts all hosts, enabling Host Header attacks.
How to fix these:
Move sensitive configuration, e.g. SECRET_KEY out of source control. Use environment variables or a secrets manager. Example:
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
Ensure DEBUG = False in production. When DEBUG = True an error page reveals stack traces and sensitive settings.
Set ALLOWED_HOSTS to the list of hostnames your site serves or only local host:
ALLOWED_HOSTS = [‘localhost’, ‘127.0.0.1’]
