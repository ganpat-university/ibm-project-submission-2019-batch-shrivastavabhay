"""web path Configuration

The `pathpatterns` list routes paths to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/paths/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a path to pathpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a path to pathpatterns:  path('', Home.as_view(), name='home')
Including another pathconf
    1. Import the include() function: from django.paths import include, path
    2. Add a path to pathpatterns:  path('blog/', include('blog.paths'))
"""
from django.urls import include, path
from . import views
from django.conf import settings
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns=[
    path('',views.index,name='index'),
    path('register/', views.register, name='register'),
    path('signin/',auth_views.LoginView.as_view(template_name='ComplaintMS/signin.html'), name='signin'),
    path('logout/', auth_views.LogoutView.as_view(template_name='ComplaintMS/logout.html'), name='logout'),
    path('password/', views.change_password, name='change_password'),
    path('passwords/', views.change_password_g, name='change_password_g'),
    path('counter/', views.counter, name='counter'),
    path('solved/', views.solved, name='solved'),

    path('login/',views.login,name='login'),
    path('list/',views.list,name='list'),
    path('pdf/',views.pdf_view,name='view'),
    path('pdf_g/',views.pdf_viewer,name='view'),
    path('aboutus/',views.aboutus,name='aboutus'),
    path('login_redirect/',views.login_redirect,name='login_redirect'),
    path('slist/',views.slist,),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('complaints/', views.complaints, name='complaints'),
    path('allcomplaints/', views.allcomplaints, name='allcomplaints'),




    #path(r'^login2/$',views.login2,name='login2'),



    #    path('password-reset/',
    #      auth_views.PasswordResetView.as_view(
    #          template_name='ComplaintMS/password_reset.html'
    #      ),
    #      name='password_reset'),
    # path(r'^password-reset-done/$',
    #      auth_views.PasswordResetDoneView.as_view(
    #          template_name='ComplaintMS/password_reset_done.html'
    #      ),
    #      name='password_reset_done'),
    # path(r'^password-reset-confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
    #      auth_views.PasswordResetConfirmView.as_view(
    #          template_name='ComplaintMS/password_reset_confirm.html'
    #      ),
    #      name='password_reset_confirm'),
    # path(r'^password-reset-complete/$',
    #      auth_views.PasswordResetCompleteView.as_view(
    #          template_name='ComplaintMS/password_reset_complete.html'
    #      ),
    #      name='password_reset_complete'),
    
   ]
urlpatterns += static(settings.STATIC_URL,document_root= settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL,document_root= settings.MEDIA_ROOT)

