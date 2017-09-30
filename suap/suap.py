# -*- coding: utf-8 
import requests
import json
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

UserModel = get_user_model()

TIPOS_BLOQUEADOS = ('Aluno')


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

        if req.status_code == 200:
            data = json.loads(req.text)
            if setToken and data['token']:
                self.setToken(data['token'])

    def setToken(self, token):
        self._token = token

    def getMeusDados(self):
        url = self._endpoint + 'minhas-informacoes/meus-dados/'

        return self.doGetRequest(url)

    def doGetRequest(self, url):
        response = requests.get(
            url, headers={'Authorization': 'JWT ' + self._token, });

        data = False

        if (response.status_code == 200):
            data = json.loads(response.text)

        return data


def getSuapUser(username, password):
    '''Recupera um usuário do suap'''
    usersuap = False
    try:
        requisicao = Suap()  # criando uma instancia da classe suap
        requisicao.autenticar(username, password)  # autenticando no servidor
        usersuap = requisicao.getMeusDados()  # recuperando dados
    except requests.exceptions.RequestException as e:
        pass
    return usersuap


class SuapBackend(ModelBackend):

    def authenticate(self, request, username=None, password=None):
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            usersuap = getSuapUser(username=username, password=password)
            # se o servidor retornar um usuário válido ele será criado no banco
            if usersuap and not usersuap['tipo_vinculo'].lower() in TIPOS_BLOQUEADOS.lower():
                user = User(username=username)
                user.set_password(password)
                user.id = usersuap['id']
                user.email = usersuap['email']
                user.first_name = usersuap['nome_usual']
                user.save()
                return user
            # Run the default password hasher once to reduce the timing
            # difference between an existing and a nonexistent user (#20760).
            UserModel().set_password(password)
        else:
            # caso o usuário do suap tenha mudado a sua senha, ela será atualizada aqui
            if not user.check_password(password):
                # veficicando se é possível recuperar um novo usuário do suap com a nova senha
                usersuap = getSuapUser(username=username, password=password)
                if usersuap:
                    # alterando a senha e salvando
                    user.set_password(password)
                    user.save()

            if user.check_password(password) and self.user_can_authenticate(user):
                return user
