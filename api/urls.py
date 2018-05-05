from rest_framework.routers import SimpleRouter
from django.conf.urls import include
from django.urls import path


from .views import UserViewSet, AssetViewSet, SecurityUserEmailsViewSet, \
    AssetLogViewSet, UserFeedbackViewSet, AssetStatusViewSet

router = SimpleRouter()
router.register('users', UserViewSet)
router.register('assets', AssetViewSet, 'assets')
router.register('security-user-emails',
                SecurityUserEmailsViewSet, 'security-user-emails')
router.register('asset-logs', AssetLogViewSet, 'asset-logs')
router.register('user-feedback', UserFeedbackViewSet, 'user-feedback')
router.register('asset-status', AssetStatusViewSet, 'asset-status')

urlpatterns = [
    path('api-auth/', include('rest_framework.urls')),
    path('o/', include('oauth2_provider.urls', namespace='oauth2_provider'))
]

urlpatterns += router.urls
