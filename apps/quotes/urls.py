from django.conf.urls import url
from . import views
urlpatterns = [
    url(r'^$', views.index),
    url(r'^register/$', views.register),
    url(r'^login/$', views.login),
    url(r'^logout$', views.logout),

    url(r'^quotes$', views.dashboard),
    # url(r'^dashboard$', views.dashboard),
    url(r'^quotes/destroy/(?P<id>\d+)/$', views.destroy_quote),
    url(r'^quotes/create$', views.create_quote),
    url(r'^quotes/like/(?P<id>\d+)/$', views.like_quote),

    url(r'^users/my_account$', views.my_account),
    url(r'^users/edit/(?P<id>\d+)$', views.edit_user),
    url(r'^users/(?P<id>\d+)/$', views.profile),
]
