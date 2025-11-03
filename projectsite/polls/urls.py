from django.urls import path

from . import views

app_name = 'polls'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('report/', views.report, name='report'),
    path('login/', views.login, name='login'),
    path('login/success/', views.login_successful, name='login_successful'),
    path('logout/', views.logout, name='logout'),
    path('search/', views.search, name='search'),
    path('leak/', views.leak_secret, name='leak_secret'),
    path('trigger-error/', views.trigger_error, name='trigger_error'),  # For demonstrating DEBUG=True
]