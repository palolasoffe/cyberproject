# OWASP 2017 Security Flaws Demonstration Guide

This document explains how to demonstrate each of the 5 security flaws for screenshots.

## Prerequisites
1. Start the Django development server: `python manage.py runserver`
2. Create a superuser if you haven't: `python manage.py createsuperuser`

---

## FLAW 1: A7:2017 - Cross-Site Scripting (XSS)

### Demonstration URL:
```
http://localhost:8000/polls/search/?q=<script>alert('XSS Attack!')</script>
```

### Screenshot "Before Fix":
- Navigate to the URL above
- You should see a JavaScript alert popup saying "XSS Attack!"
- Take a screenshot showing the alert

### Alternative XSS Demo (more visible):
```
http://localhost:8000/polls/search/?q=<h1 style="color:red">INJECTED HTML!</h1>
```
- Shows red heading injected into the page

### To Apply Fix:
In `polls/templates/polls/search.html`:
- Change `{{ q|safe }}` to `{{ q }}`
- OR uncomment the fix line in the template

### Screenshot "After Fix":
- Same URL should now show the literal text `<script>alert('XSS Attack!')</script>` instead of executing it

---

## FLAW 2: A2:2017 - Broken Authentication

### Demonstration Steps:

#### Before Fix:
1. Navigate to: `http://localhost:8000/polls/login/`
2. Enter username: `demo`
3. Enter password: `demo`
4. Click Login
5. **Screenshot**: You successfully log in (even though demo/demo is not a real user!)
6. You'll see the "Login Successful" page

#### To Apply Fix:
In `polls/views.py` in the `insecure_login()` function:
- Comment out lines 63-66 (the vulnerable code)
- Uncomment lines 69-74 (the fix)

#### After Fix:
1. Try to login with demo/demo again
2. **Screenshot**: You should get "Invalid credentials" error
3. Only real Django users can now log in

---

## FLAW 3: A3:2017 - Sensitive Data Exposure

### Demonstration URL:
```
http://localhost:8000/polls/leak/
```

### Screenshot "Before Fix":
- Navigate to the URL above
- You'll see the page displays: "Leaked secret: django-insecure-_#v21hank^hk0nt6*h$!ni@zik&ir)j^6jhp*3mpebch3=pz72"
- This exposes Django's SECRET_KEY which should NEVER be visible

### To Apply Fix:
In `polls/views.py` in the `leak_secret()` function:
- Comment out lines 92-93 (the vulnerable code)
- Uncomment line 96 (the fix)

### Screenshot "After Fix":
- Same URL should now show: "Secret information is not available"

---

## FLAW 4: Cross-Site Request Forgery (CSRF)

### Demonstration Steps:

#### Before Fix:
1. Make sure you're logged in to `http://localhost:8000/polls/`
2. Open the file `csrf_attack_demo.html` (in your project root) in a browser
3. The page will auto-submit a form to your polls application
4. **Screenshot**: You'll see "Report received: MALICIOUS REPORT: This was submitted via CSRF attack from an external site!"
5. This proves the CSRF attack worked!

#### To Apply Fix:
In `polls/views.py`:
- Remove the `@csrf_exempt` decorator from the `report()` function (line 124)

In `polls/templates/polls/report.html`:
- Uncomment the `{% csrf_token %}` line

#### After Fix:
1. Try opening `csrf_attack_demo.html` again
2. **Screenshot**: You should get a "403 Forbidden - CSRF verification failed" error
3. This proves CSRF protection is now working

---

## FLAW 5: A6:2017 - Security Misconfiguration (DEBUG=True)

### Demonstration URL:
```
http://localhost:8000/polls/trigger-error/
```

### Screenshot "Before Fix":
- Navigate to the URL above
- You'll see Django's detailed error page with:
  - Full stack trace showing the code
  - Local variables and their values
  - Settings information
  - Request information
  - **This exposes sensitive information to attackers!**
- Take a screenshot of this detailed error page

### To Apply Fix:
In `projectsite/settings.py`:
- Comment out line 32: `DEBUG = True`
- Uncomment lines 35-38 (the fix)
- Set environment variable or change to: `DEBUG = False`

### Screenshot "After Fix":
- Same URL should show a generic "Server Error (500)" page
- No sensitive information is exposed

---

## Summary Table for Your Report

| Flaw # | OWASP 2017 | Vulnerability | Demonstration URL | Visible Impact |
|--------|-----------|---------------|-------------------|----------------|
| 1 | A7 | XSS | `/polls/search/?q=<script>alert('XSS')</script>` | Alert popup appears |
| 2 | A2 | Broken Auth | `/polls/login/` (demo/demo) | Unauthorized access |
| 3 | A3 | Sensitive Data | `/polls/leak/` | SECRET_KEY exposed |
| 4 | - | CSRF | Open `csrf_attack_demo.html` | External form submission works |
| 5 | A6 | Misconfiguration | `/polls/trigger-error/` | Detailed error page with stack trace |

---

## Quick Test Checklist

Before taking screenshots, verify:
- [ ] Server is running (`python manage.py runserver`)
- [ ] XSS alert appears
- [ ] demo/demo login works
- [ ] Secret key is visible at /polls/leak/
- [ ] CSRF attack HTML file submits successfully
- [ ] Detailed error page appears at /polls/trigger-error/

After applying fixes, verify:
- [ ] XSS shows escaped text instead of executing
- [ ] demo/demo login fails
- [ ] Secret endpoint shows safe message
- [ ] CSRF attack gets 403 error
- [ ] Error page is generic without details

---

## Notes for Your Report

Remember to explain in your documentation:
1. **Why each flaw is dangerous** (impact)
2. **How an attacker could exploit it** (attack vector)
3. **How the fix prevents the attack** (solution)
4. **Which OWASP 2017 category it falls under**

Good luck with your assignment! 🎓
