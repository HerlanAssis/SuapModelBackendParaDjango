import requests
import json
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

UserModel = get_user_model()


class Suap(object):
    """docstring for Suap"""
    _token = ''
    _endpoint = 'https://suap.ifrn.edu.br/api/v2/'

    def __init__(self, token=False):
        super(Suap, self).__init__()
        if(token):
            self._token = token

    def autenticar(self, username, password, accessKey=False, setToken=True):
        # Se estiver acessando com uma chave de acesso...
        if accessKey:
            url = self._endpoint + 'autenticacao/acesso_responsaveis/'

            params = {
                'matricula': username,
                'chave': password,
            }
        else:
            url = self._endpoint + 'autenticacao/token/'

        params = {
            'username': username,
            'password': password,
        }
                
        req = requests.post(url, data=params)          

        data = False

        if req.status_code==200:
            data = json.loads(req.text)                
            if setToken and data['token'] :
                self.setToken(data['token'])                       

    def setToken(self, token):
        self._token = token

    def getMeusDados(self):
        url = self._endpoint + 'minhas-informacoes/meus-dados/'

        return self.doGetRequest(url)

    def doGetRequest(self, url):
        response = requests.get(url, headers =  {'Authorization': 'JWT ' + self._token, });

        data = False

        if (response.status_code == 200):
            data = json.loads(response.text)
    
        return data


class SuapBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).        

            try:
                requisicao = Suap()
                requisicao.autenticar(username, password)                
                usersuap = requisicao.getMeusDados()
                                
                if usersuap:
                    user = User(username=username)                            
                    user.set_password(password)
                    user.id = usersuap['id']
                    user.email = usersuap['email']
                    user.first_name = usersuap['nome_usual']
                    user.save()
            except requests.exceptions.RequestException as e:                
                raise e             

            UserModel().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user
