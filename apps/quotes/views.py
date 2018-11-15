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

def dashboard(request):
    signed_in = request.session.get('id', False)
    if not signed_in:
        return redirect('/')
    user = User.objects.get(id = request.session['id'])
    # print()
    # msgs = Message.objects.all()
    # comment = Comment.objects.all().values()
    # user_messages = []
    # for msg in msgs:
        # comments = []
        # for comment in msg.comments.all():
            # user = User.objects.get(id=comment.user_id)
            # comment_object = {
                    # 'comment': comment.comment,
                    # 'created_at': comment.created_at,
                    # 'username': user.first_name + ' ' + user.last_name,
                    # }
            # comments.append(comment_object)
        # message_object = {
            # 'message': msg.message,
            # 'comments': comments
        # }
        # user_messages.append(message_object)


    context = {
        'user': user,
    }

    return render(request, "quotes/dashboard.html", context)
