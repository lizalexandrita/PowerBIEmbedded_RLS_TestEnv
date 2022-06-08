"""
Esse script simula o backend necessário para gerar as visualizações do Power BI Embedded e os testes de RLS
"""

import requests
import json
# import psycopg2
import pyodbc
import pandas as pd
import numpy as np
import hashlib

__author__ = "Liz Alexandrita de S. Barreto"
__copyright__ = "Copyleft 2020, Microserviço de Teste de RLS no Power BI Embedded"
__credits__ = ["Liz Alexandrita de S. Barreto"]
__license__ = "GPL"
# Alterações de arquitetura
# 0.0.2 - listagem de relatórios dinâmica,
# 0.0.3 - inclusão de role e alteração da estrutura da tabela de RLS
__version__ = "0.0.3"
__maintainer__ = "Liz Alexandrita de S. Barreto"
__email__ = "liz.asbarreto@gmail.com"
__status__ = "Testes"


def rls():
    """ Função que conecta no banco de cadastro trazendo as infos necessárias
    para construção do RLS e dos JSONs usados no backend.

        :return dataframe com tabela de cadastro de escritórios e assessores, e suas hashs para o RLS
        [
        'parent_id_advisor',
        'name',
        'id_advisor',
        'cpf_cnpj',
        'roles',
        'RLS',
       'username',
       'parent_username'
       'gestor_username',
       'gestor_parent_username'
       ]
    """
    # Variáveis para conexão no banco de cadastro - retiradas do código e configuradas através da DSN

    # Conexão e Query da Tabela de Cadastro
    conn = pyodbc.connect('DSN=Redshift')
    cur = conn.cursor()
    # TODO: a query deveria ser injetada por um arquivo separado?
    sql_query = 'SELECT * FROM public.tbl_powerbi_rls;'
    df = pd.read_sql_query(sql_query, conn)
    # TODO: usar with?
    cur.close()
    conn.close()

    # Escolha apenas das colunas para simular o algoritmo de criação dos insumos para o RLS no PowerBI Embedded
    df = df[['parent_id_advisor', 'name', 'id_advisor', 'cpf_cnpj', 'fl_gestor']]

    # Teste fl_gestor - Teste para Inclusão de Eng. Dados
    df['fl_gestor'] = np.where((df['id_advisor'] == 9999999) | (df['parent_id_advisor'] == 9999999), '1', '0')

    # Criação dos Roles
    conditions = [
        (df['fl_gestor'] == '0') & (df['parent_id_advisor'] == 0),  # Escritório
        (df['fl_gestor'] == '0') & (df['parent_id_advisor']  > 0),  # Assessor
        (df['fl_gestor'] == '1') & (df['parent_id_advisor'] == 0),  # Gestor Escritório
        (df['fl_gestor'] == '1') & (df['parent_id_advisor']  > 0)   # Gestor Assessor
    ]
    values = ['Escritório', 'Assessor', 'GestorEscritório', 'GestorAssessor']
    df['roles'] = np.select(conditions, values)

    # Criação do RLS
    conditions = [
        (df['fl_gestor'] == '0') & (df['parent_id_advisor'] == 0),  # Escritório
        (df['fl_gestor'] == '0') & (df['parent_id_advisor']  > 0),  # Assessor
        (df['fl_gestor'] == '1') & (df['parent_id_advisor'] == 0),  # Gestor Escritório
        (df['fl_gestor'] == '1') & (df['parent_id_advisor']  > 0)   # Gestor Assessor
    ]
    values = ['ESC' + df['id_advisor'].astype('str'),  # Escritório
              'ESC' + df['parent_id_advisor'].astype('str') + 'ASS' + df['id_advisor'].astype('str'),  # Assessor
              'GESC' + df['id_advisor'].astype('str'),  # Gestor Escritório
              'GESC' + df['parent_id_advisor'].astype('str') + 'ASS' + df['id_advisor'].astype('str')  # Gestor Assessor
              ]
    df['RLS'] = np.select(conditions, values)

    # Criação do hash de forma pythonica
    df['hash'] = [hashlib.md5(x.encode()).hexdigest()
                  for x in
                  df['cpf_cnpj'].astype('str') +
                  df['RLS'].astype('str') +
                  df['roles'].astype('str') +
                  'ControlMot']

    # Username
    df['username'] = df['hash']

    # Criação do parent_username como um left join
    parent = df[['id_advisor', 'hash']]
    parent = parent.rename(columns={'id_advisor': 'a', 'hash': 'parent_username1'})
    df = pd.merge(df, parent, how='left', left_on='parent_id_advisor', right_on='a')
    df['parent_username'] = np.where((df['parent_id_advisor'] > 0),
                                     df['parent_username1'].astype('str'),
                                     np.where((df['parent_id_advisor'] == 0),
                                              df['username'].astype('str'),
                                              '')
                                     )
    df = df.drop(columns=['parent_username1', 'a'])

    # Criação do gestor_username
    df['gestor_username'] = np.where((df['fl_gestor'] == '1'),
                                     df['hash'].astype('str'),
                                     '')

    # Criação do gestor_parent_username como um left join
    gestor_parent = df[['id_advisor', 'gestor_username']]
    gestor_parent = gestor_parent.rename(columns={'id_advisor': 'a', 'gestor_username': 'gestor_parent1'})
    df = pd.merge(df, gestor_parent, how='left', left_on='parent_id_advisor', right_on='a')
    df['gestor_parent_username'] = np.where((df['parent_id_advisor'] == 0) & (df['fl_gestor'] == '1'),
                                            df['gestor_username'].astype('str'),
                                            np.where((df['fl_gestor'] == '1') & (df['parent_id_advisor'] > 0),
                                                     df['gestor_parent1'].astype('str'),
                                                     '')
                                            )
    df = df.drop(columns=['hash', 'gestor_parent1', 'a'])

    return df


def make_json(config_file, file_name, rls_username, rls_str, roles, datasets):
    """
    Função que gera os JSON de teste de RLS

    :param config_file: string com o nome do arquivo de configurações do report
    :param file_name: string com o nome do arquivo a ser criado
    :param rls_username: string com hash com o username buscado
    :param rls_str: string com o padrão de nomenclatura para indicar o RLS
    :param roles: vetor de string(s) com o papel a visualizar o relatório (atualmente escritório ou assessor)
    :param datasets: vetor de string(s) com o ID do dataset do relatório
    :return: retorna um vetor com o nome do arquivo e um booleano indicando o estado do arquivo, True caso o arquivo tenha sido gravado com sucesso e False caso contrário.
    """
    # TODO: criar exceção para retornar sucesso ou falha de criação do arquivo
    json_file = {
            "accessLevel": "View",
            "allowSaveAs": "false",
            "identities": [
                {
                    "username": rls_username,
                    "RLS": rls_str,
                    "roles": roles,
                    "datasets": datasets
                }
            ]
    }
    try:
        with open('temp/' + file_name, 'w') as outfile:
            json.dump(json_file, outfile)
        return [file_name, True, config_file]
    except FileExistsError("O arquivo " + file_name + " não foi gravado"):
        return [file_name, False, config_file]


def make_all_json(df, config_file):
    """
    Função que cria todos os arquivos json de rls para testes e devolve o sucesso ou falha de cada numa matriz

    :param config_file: arquivo de configuração em JSON com infos do relatório para extrair o dataset_id
    :param df: dataframe que contém a tabela de RLS
    :return: dataframe com os nomes e estado dos arquivos (True para gravado com sucesso e False caso contrário)
    """
    # Inicialização das configurações do relatório
    with open(config_file, "r") as f:
        report_config = json.load(f)
    config_file = config_file.replace('temp\\', '')
    dataset_id = report_config['report']['dataset_id']
    lt = [make_json(config_file=config_file,
                    file_name="rls_" + x + "_" + a + '_' + config_file[:-7] + ".json",
                    rls_username=y,
                    rls_str=z,
                    roles=[a],
                    datasets=[dataset_id]
                    )
          for x, y, z, a in zip(df.name.replace({r'(\w+),\s+(\w+)': r'\2 \1',
                                                 ' ': '_',
                                                 '\/': ''},
                                                regex=True),
                                df.username, df.RLS, df.roles)]
    return pd.DataFrame(lt, columns=['file_name', 'file_is_written', 'config_file'])


def authenticate(config_file='MasterConfig.json'):
    """ Função que autentica a aplicação no Azure Active Directory

        :param
            config_file: arquivo de configuração do relatório em formato JSON
        :return string com o token de autenticação no AAD
    """
    # Inicialização das configurações de autenticação e relatório
    with open(config_file, "r") as f:
        report_config = json.load(f)
    client_id = report_config['auth']['client_id']
    client_secret = report_config['auth']['client_secret']
    endpoint_aad = report_config['auth']['AAD']

    # Autenticação no Azure Active Directory
    body_aad = 'client_id=' + client_id + '&scope=' \
               + 'https%3A//analysis.windows.net/powerbi/api/.default' \
               + '&grant_type=client_credentials&client_secret=' + client_secret
    headers_aad = {'Content-Type': 'application/x-www-form-urlencoded'}
    response_aad = requests.request("POST", endpoint_aad, headers=headers_aad, data=body_aad)
    dict_response_aad = json.loads(response_aad.text)
    auth_token = dict_response_aad['token_type'] + ' ' + dict_response_aad['access_token']

    return auth_token


def embed_report(auth_token, workspace_id, report_id, json_file):
    """
    Função que gera o token de embed do relatório

    :param auth_token: string com token de autenticação no Azure Active Directory
    :param workspace_id: string com ID do workspace que está publicado o relatório a ser embedado
    :param report_id: string com ID do relatório a ser embedado
    :param json_file: string com o nome do arquivo JSON com as infos de RLS
    :return: dataframe com as informações necessárias para embedar o arquivo na API javascript do Power BI:
        [
        'report_token',
        'report_id',
        'embed_url'
        ]
    """
    endpoint = "https://api.powerbi.com/v1.0/myorg/groups/" + workspace_id + "/reports/" + report_id + "/GenerateToken"
    with open("temp/" + json_file, "r") as f:
        body = f.read().replace('\n', '').replace(' ', '')
    headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
    response = requests.request("POST", endpoint, headers=headers, data=body)
    dict_response = json.loads(response.text)
    report_token = dict_response['token']
    embed_url = "https://app.powerbi.com/reportEmbed?reportId=" + report_id + "&groupId=" + workspace_id

    return pd.DataFrame(data=[[report_token, report_id, embed_url]], columns=['report_token', 'report_id', 'embed_url'])


def list_reports(auth_token, workspace_id):
    """
    Função que lista os relatórios de um dado workspace

    :param auth_token: string com token de autenticação na Azure
    :param workspace_id: string com o id do workspace
    :return: dataframe com a lista de relatórios
    """

    endpoint = "https://api.powerbi.com/v1.0/myorg/groups/" + workspace_id + "/reports"
    headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
    response = requests.request("GET", endpoint, headers=headers)
    dict_response = json.loads(response.text)
    list_report = pd.DataFrame(dict_response['value'])
    list_report = list_report.drop(columns=['reportType', 'webUrl', 'isFromPbix', 'isOwnedByMe'])
    list_report = list_report.rename(columns={'id': 'report_id', 'name': 'report_name',
                                              'embedUrl': 'embed_url', 'datasetId': 'dataset_id'})
    return list_report


def list_workspaces(auth_token):
    """
    Função que lista os workspaces de um cliente da Azure

    :param auth_token:  string com token de autenticação na Azure
    :return: dataframe com a lista de workspaces do cliente
    """
    endpoint = "https://api.powerbi.com/v1.0/myorg/groups/"
    headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
    response = requests.request("GET", endpoint, headers=headers)
    dict_response = json.loads(response.text)
    list_workspace = pd.DataFrame(dict_response['value'])
    list_workspace = list_workspace.drop(columns=['isReadOnly', 'isOnDedicatedCapacity'])
    list_workspace = list_workspace.rename(columns={'id': 'workspace_id', 'name': 'workspace_name'})
    return list_workspace


def turn_report_into(auth_token, from_workspace_id, from_report_id, to_workspace_id, to_report_id):
    """
    Função para migrar um relatório de um workspace para outro, ambos já existentes

    :param auth_token: string com o token de atenticação da Azure
    :param from_workspace_id: string com o id do workspace de origem
    :param from_report_id:  string com o id do relatório de origem
    :param to_workspace_id:  string com o id do workspace de destino
    :param to_report_id:  string com o id do relatório de destino
    :return: string com a resposta da chamada
    """
    endpoint = 'https://api.powerbi.com/v1.0/myorg/groups/' + from_workspace_id \
               + '/reports/' + from_report_id + '/UpdateReportContent'
    headers = {'Content-Type': 'application/json', 'Authorization': auth_token}
    body = '{  "sourceReport": {"sourceReportId": "' + to_workspace_id \
           + '","sourceWorkspaceId": "' + to_report_id + '"},"sourceType": "ExistingReport"}'
    response = requests.request("POST", endpoint, headers=headers, data=body)
    dict_response = json.loads(response.text)
    return dict_response


def create_config_files(list_report, workspace_id):
    """
    Função que cria todos os arquivos de configuração de todos os relatórios de um dado workspace
    :rtype: DataFrame
    :param list_report: dataframe com a listagem de todos os relatórios de um workspace
    :param workspace_id: string com o id do workspace que os relatórios se referem
    :return: dataframe com a listagem dos arquivos de configuração, nome e status de gravação no sistema
    """
    config_frame = pd.DataFrame()
    with open('MasterConfig.json', "r") as f:
        report_config = json.load(f)
    client_id = report_config['auth']['client_id']
    client_secret = report_config['auth']['client_secret']
    for report_id, dataset_id, report_name in zip(list_report['report_id'],
                                                  list_report['dataset_id'],
                                                  list_report['report_name']):
        # configs no formato json
        config = {
            "auth": {"client_id": client_id,
                     "client_secret": client_secret},
            "report": {"workspace_id":  workspace_id,
                       "report_id": report_id,
                       "dataset_id": dataset_id
                       }
        }
        # nome do arquivo
        file_name = 'report' + report_name + '__workspace_' + workspace_id + '.config'
        # escreve o arquivo
        try:
            with open('temp/' + file_name, 'w') as outfile:
                json.dump(config, outfile)
            config_frame = config_frame.append([[file_name, True, report_name]])
        except FileExistsError("O arquivo " + file_name + " não foi gravado"):
            config_frame = config_frame.append([[file_name, False, report_name]])
    return config_frame
