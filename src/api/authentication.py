from decouple import config
from django.contrib.auth import get_user_model
from rest_framework.authentication import TokenAuthentication
from rest_framework import exceptions
from firebase_admin import auth, credentials, initialize_app

User = get_user_model()

private_key = config('PRIVATE_KEY').replace('\\n', '\n')

payload = {
  "type": "service_account",
  "project_id": "andela-resource-tracker-202707",
  "private_key_id": "f1fb8a40b2b27889da8702967f482b2104cbb261",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuNO9Ta/VUuTPE\nKvA8ngrMD4FLfdBNYFGle4I8QtxnaBOio7IumQwN5VKu04227FujofHl33iW4b8Z\niXgnyYkFlVEQsjD3+Xi5vUjD6SrK1YZ4drcAeVKyqLPrg0GoSLIftxZlRjXmu15W\noUwwnwAbtRYzJvdW2BgImZ57VdVZ7J6teD3lTrrSGM/bv0owsIDR/mVHTtHLwteg\nbkyIGlJgKBTwZYGzdRZCigk0f3mvHKcO32pCRen9KvRnOYi8EKwKEjVU2BZdSOzQ\nHU0z6zcp20iX+cW9mDlPkmqtKBzcK7Mbh7y+V8uKg8tJEpDE2m1rfwCrZNUrHZQZ\ndyay1MPPAgMBAAECggEACxlAQ3ZV/lHWTyHVMGd5P0r1l9OqLmPROn5wllpEJH+9\npdemsHqmXp7vnPJ0IuVSvqLAqz6I4O6notQz8tpPf9WQK+95AzNs/O28Rw8B35j+\n+jRwsE0KdxYccF1qah2c4OcPPDXe6pZMClo4ZRicLye4WbCags6S/r6axDd8YkAq\njLnDQZYN9E8MAhe5yDJ/+ltDhM/b/3gnwqmFFKdRqVhXz4BEpJhlSO2mgBxVGpsm\n/47Ylm5B9Ckwp1kvNMs/J0OykKo668DeTWuY9ihb8DtEAqXBoyDx+9Sft4HcbUPo\nc/kmIGJGuavgkJLv31wvmCzenGQk53BrP0AkTkqzYQKBgQDut+QSMpgANnt54y4Z\n+EcPrqA3v+cph2Eq6ysPWL4evFvErSe3jtE8l3mhTfvPpKDIhkCt/lgs/XGrML1k\nc9/CI+TE3UlyzHVJvNUVvu/1UE8RbMEfxtLQNvTWq3gZkLIPdi/FHPqMYq7lhiQJ\nx3Ekr86uZMyay9H/hE0HVvvgqQKBgQC60XePL9VfWkae3Ok9oc+o1tCNvnX0auBa\nQQR4hlvGDd5PNaALU5+bSyeoanLUvReBLCufXsXHpEHXGQYkfNnk4YwdwTS9RvAK\nrPpoeyeE2TqIT51D2cFLs0pDBnR2SfE3QLFlSSGftJvnPwSSig75QAN0KmKvIwFZ\nqUWJMsmztwKBgQDlccx+DTD562Ps+IWkInWyxgZq70FxMhUb2mNN4d8CzcpqlH+7\nN0M3OOSIPNtObg64Dgn28qOvwn5Rq4wuFA26nSNScNsawxfsotowh5A+Ok11ExHg\nyApyZJAaET9jWyc6Iz+w9rR+4I74P2E+IPtH5s8B4hKiqksSjAg5iMqZ2QKBgC1z\nGGs1b+uqwtOTWwsreqHQ4Rwa4gd8mOhcOQI5bcpZRWRv32fiCEp3lkZa32TyO+2p\nGVPEcsmHJJ138Q6fcUNFvBjhEDucLnnqa2FP1OV1E9BlzhTbvTL1g3Oa9mpwwsZ2\nbrH9gLih7+vqYOplvA7Xi/+O8EM7ePCfRdODD58xAoGAUO8ZN4YIuohvhZgZkUGm\nxnricDTxd9ZA/hqHBkw/hUVjz/wbsN87eHzBAZHwQE32NyN3WmOJQEglslpAszZB\nlCGSQ5xvNJd4Atc6KdCdIl8oxUolSb6Ozd62BJgbahbW/MzB3wOPFzYQz5VCCXbf\nodGMqYizA/Qy7QseFUzUKSw=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-senn4@andela-resource-tracker-202707.iam.gserviceaccount.com",
  "client_id": "111345208485655344399",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-senn4%40andela-resource-tracker-202707.iam.gserviceaccount.com"
}

cred = credentials.Certificate(payload)
initialize_app(cred)


class FirebaseTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        try:
            token = auth.verify_id_token(key)
            email = token['email']
            user = User.objects.get(email=email)
        except Exception:
            raise exceptions.AuthenticationFailed('Unable to authenticate.')

        if not user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or deleted.')
        return (user, token)