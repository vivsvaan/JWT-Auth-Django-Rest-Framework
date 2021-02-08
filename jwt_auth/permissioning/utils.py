
def get_auth_token(request):
    return request.META.get('HTTP_AUTHORIZATION', '')
