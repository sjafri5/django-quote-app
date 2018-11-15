from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from apps.quotes.models import *
import re
import bcrypt

def index(request):
    return render(request, "quotes/index.html")

def register(request):
    if request.method == 'POST':
        error = False
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        valid_email = re.search(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', email, re.I)
        if (not valid_email):
            messages.error(request, 'invalid email')
            error = True

        pw = request.POST.get("password")
        pw_conf = request.POST.get("password_confirmation")
        if (pw != pw_conf):
            messages.error(request, 'pw doesnt match')
            error = True

        if(error):
            return redirect('/')

        pw_hash = bcrypt.hashpw(request.POST.get("password").encode(), bcrypt.gensalt())
        user = User.objects.create(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=pw_hash
                )
        request.session['id'] = user.id
        
        messages.success(request, 'registered!')
        return redirect('/dashboard')

def login(request):
    try:
        user = User.objects.get(email=request.POST.get("email"))
    except User.DoesNotExist:
        messages.error(request, 'invalid email/password')
        return redirect('/')

    if (bcrypt.checkpw(request.POST.get("password").encode(), user.password.encode())):
        messages.success(request, 'welcome back!')
        request.session['id'] = user.id
        return redirect('/dashboard')
    else:
        messages.error(request, 'invalid email/password')
        return redirect('/')

def logout(request):
    del request.session['id']
    return redirect('/')

def destroy_quote(request, id):
    quote = Quote.objects.get(id = id)
    quote.delete()
    return redirect('/dashboard')

def create_quote(request):
    if request.method == 'POST':
        print('ffffffffffffff')
        print(request.POST)

        Quote.objects.create(
                description = request.POST['description'],
                author = request.POST['author'],
                user_id = request.session['id'])
    return redirect('/dashboard')

def dashboard(request):
    signed_in = request.session.get('id', False)
    if not signed_in:
        return redirect('/')
    user = User.objects.get(id = request.session['id'])
    quote_objects = Quote.objects.all()
    quotes = []
    for quote_object in quote_objects:
        quotes= []
        deletable = user.id == quote_object.user.id
        quote = {
            'id': quote_object.id,
            'description': quote_object.description,
            'author':  quote_object.author,
            'posted_by_id':  quote_object.user.id,
            'posted_by':  quote_object.user.first_name + ' ' + quote_object.user.last_name,
            'deletable': deletable
        }
        quotes.append(quote)

    context = {
        'user': user,
        'quotes': quotes,
    }

    return render(request, "quotes/dashboard.html", context)
