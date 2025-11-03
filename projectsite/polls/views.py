from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.views import generic
from django.views.decorators.csrf import csrf_exempt

from .models import Question
from django.contrib.auth import authenticate
from django.conf import settings

class IndexView(LoginRequiredMixin, generic.ListView):
    login_url = '/polls/login/'
    redirect_field_name = 'next'
    template_name = 'polls/index.html'
    context_object_name = 'latest_question_list'

    def get_queryset(self):
        return Question.objects.order_by('-pub_date')[:5]


# Security flaws from OWASP 2017

def search(request):
    """
    FLAW 1: Cross-Site Scripting (XSS)
    
    The search view passes user input directly to the template where it's 
    rendered with the |safe filter, which disables Django's auto-escaping. This allows 
    an attacker to inject malicious JavaScript.
    
    Example attack: /polls/search/?q=<script>alert('XSS')</script>
    """
    #FIX: Remove the |safe filter from the template (search.html) to enable Django's built-in auto-escaping
    
    q = request.GET.get('q', '')
    return render(request, 'polls/search.html', {'q': q})


def login(request):
    """
    FLAW 2: Broken Authentication
    
    This view has two authentication flaws:
    1. Hardcoded credentials (username='demo', password='demo') bypass proper authentication
    2. Manual session management instead of using Django's authentication system
    
    This allows attackers to bypass authentication checks and potential session hijacking.
    """
    message = ''
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        # FIX: uncomment and replace the vulnerable code below
        #user = authenticate(request, username=username, password=password)
        #if user is not None:
        #    login(request, user)
        #    return HttpResponseRedirect(reverse('polls:login_successful'))
        #else:
        #    message = 'Invalid credentials'
        user = authenticate(request, username=username, password=password)
        if user is not None or (username == 'demo' and password == 'demo'):
            request.session['user'] = username
            return HttpResponseRedirect(reverse('polls:login_successful'))
        else:
            message = 'Invalid credentials'

    return render(request, 'polls/login.html', {'message': message})



def leak_secret(request):
    """
    FLAW 3: Sensitive Data Exposure
    
    This endpoint exposes Django's SECRET_KEY, which is used for:
    - Cryptographic signing of session data
    - CSRF token generation
    - Password reset tokens
    
    Exposing this allows attackers to forge sessions, CSRF tokens, and compromise 
    the entire application's security.
    """
    # FIX: uncomment and remove the vulnerable code below:
    #return HttpResponse('No secret information here :(')
    secret = getattr(settings, 'SECRET_KEY', 'no-secret')
    return HttpResponse(f"Leaked secret: {secret}")


def login_successful(request):
    #Simple page for showing that login was successful and user is allowed to use the site
    return render(request, 'polls/login_successful.html')


def logout(request):
    #Clear demo session and log out user, then redirect to login
    try:
        del request.session['user']
    except KeyError:
        pass
    return HttpResponseRedirect(reverse('polls:login'))

@csrf_exempt
def report(request):
    """
    FLAW 4: Cross-Site Request Forgery (CSRF)
    
    Description: The @csrf_exempt decorator disables Django's CSRF protection for this view.
    An attacker can craft a malicious website that submits a form to this endpoint while 
    a user is authenticated, causing unwanted actions to be performed without the user's consent.
    
    Example attack: Attacker creates a hidden form on their site that auto-submits to 
    /polls/report/ when the victim visits, potentially submitting false reports or spam.
    """
    # FIX: 
    # Remove the @csrf_exempt decorator above
    # Add {% csrf_token %} inside the <form> tag in report.html
    if request.method == 'POST':
        data = request.POST.get('data', '')
        # pretend to save the report
        return HttpResponse('Report received: ' + data)
    return render(request, 'polls/report.html')


def trigger_error(request):
    """
    Helper view to demonstrate FLAW 5 (Security Misconfiguration with DEBUG=True)
    
    This view intentionally causes an error to show Django's debug page which
    exposes sensitive information when DEBUG=True.
    
    Visit /polls/trigger-error/ to see the detailed error page with:
    - Full stack trace
    - Local variables
    - Settings and environment variables
    - Database queries
    """
    # Intentionally cause an error
    result = 1 / 0  # ZeroDivisionError
    return HttpResponse("This won't be reached")