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

        if User.objects.filter(email=request.POST['email']).exists():
            messages.error(request, 'duplicate email')
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
        return redirect('/quotes')

def login(request):
    try:
        user = User.objects.get(email=request.POST.get("email"))
    except User.DoesNotExist:
        messages.error(request, 'invalid email/password')
        return redirect('/')

    if (bcrypt.checkpw(request.POST.get("password").encode(), user.password.encode())):
        messages.success(request, 'welcome back!')
        request.session['id'] = user.id
        return redirect('/quotes')
    else:
        messages.error(request, 'invalid email/password')
        return redirect('/')

def logout(request):
    del request.session['id']
    return redirect('/')

def destroy_quote(request, id):
    quote = Quote.objects.get(id = id)
    quote.delete()
    return redirect('/quotes')

def like_quote(request, id):
    user = User.objects.get(id = request.session['id'])
    quote = Quote.objects.get(id = id)
    quote.likes.add(user)
    quote.save()
    return redirect('/quotes')

def create_quote(request):
    if request.method == 'POST':
        if len(request.POST['description']) < 10 or len(request.POST['author']) < 3:
            messages.error(request, 'Please enter a value for both author and quote. Author must be 3 characters; Quote must be at least 10.')
            return redirect('/quotes')

        Quote.objects.create(
                description = request.POST['description'],
                author = request.POST['author'],
                user_id = request.session['id'])
    return redirect('/quotes')

def profile(request, id):
    signed_in = request.session.get('id', False)
    if not signed_in:
        return redirect('/')

    user = User.objects.get(id=id)
    quotes = Quote.objects.filter(user_id=id)
    context = {
            'user': user,
            'quotes': quotes
            }

    return render(request, "quotes/profile.html", context)

def my_account(request):
    signed_in = request.session.get('id', False)
    if not signed_in:
        return redirect('/')

    user = User.objects.get(id = request.session['id'])
    context = { 'user': user }
    return render(request, "quotes/my_account.html", context)

def edit_user(request, id):
    if request.method == 'POST':
        error = False
        if not request.POST['first_name'] or not request.POST['last_name']:
            messages.error(request, 'First and Last name must be at least one character long')
            error = True

        valid_email = re.search(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', request.POST['email'], re.I)

        if not valid_email:
            messages.error(request, 'invalid email')
            error = True

        if User.objects.filter(email=request.POST['email']).exclude(id=id).exists():
            messages.error(request, 'duplicate email')
            error = True

        if error:
            return redirect('/users/my_account')


        user = User.objects.get(id = request.session['id'])
        user.first_name = request.POST['first_name']
        user.last_name = request.POST['last_name']
        user.email= request.POST['email']
        user.save()
        messages.success(request, 'updated!')

        context = { 'user': user }
        return redirect('/users/my_account')

def dashboard(request):
    signed_in = request.session.get('id', False)
    if not signed_in:
        return redirect('/')
    user = User.objects.get(id = request.session['id'])
    quote_objects = Quote.objects.all()
    quotes = []
    for quote_object in quote_objects:
        deletable = user.id == quote_object.user.id
        likeable = not quote_object.likes.all().filter(id=user.id).exists() 
        
        quote = {
            'id': quote_object.id,
            'description': quote_object.description,
            'likes': quote_object.likes.all().count(),
            'likeable': likeable,
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
