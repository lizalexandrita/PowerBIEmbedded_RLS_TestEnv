from os import environ, remove
# import requests
from flask import render_template, Flask  # , Response, stream_with_context
import glob
import json
import pandas as pd
import pbi_embed as bk

app = Flask(__name__)

# Limpa arquivos anteriores - que podem ter sido alterados
all_reports = glob.glob('temp/report*.config')
for i in all_reports:
    remove(i)
all_reports = glob.glob('temp/rls*.json')
for i in all_reports:
    remove(i)


# Autentica no Azure a primeira vez
auth_token = bk.authenticate()

# Cria tabela de escolha de workspaces e relatórios
list_workspace = bk.list_workspaces(auth_token=auth_token)
wks_table = pd.DataFrame()

for wid, wname in zip(list_workspace['workspace_id'], list_workspace['workspace_name']):
    # Cria arquivos de configuração dos relatórios do workspace selecionado
    list_report = bk.list_reports(auth_token=auth_token, workspace_id=wid)
    configs = bk.create_config_files(list_report=list_report, workspace_id=wid)
    # Lista Workspaces e Relatórios na Tabela
    df = pd.DataFrame({
        wname: '<a href="workspace/workspace_id=''' + wid +
               '''/report/report_id=''' + list_report['report_id'] +
               '''/name/report_name=''' + list_report['report_name'] +
               '''">''' + list_report['report_name'] + '''</a>'''
    })
    wks_table = pd.concat([wks_table, df], ignore_index=False, axis=1)

wks_table = wks_table.to_html(classes='table100-head', index=False, escape=False, border=0)

# Tabela de RLS individualizado
rls_df = bk.rls()
rls_table = rls_df.drop(columns=['username', 'parent_username', 'parent_id_advisor',
                                 'gestor_username', 'gestor_parent_username', 'fl_gestor'])
json_table = pd.DataFrame()
all_reports = glob.glob('temp/report*.config')
for report in all_reports:
    with open(report, "r") as f:
        report_config = json.load(f)
    json_table[report.replace('temp\\', '')] = bk.make_all_json(df=rls_df, config_file=report)['file_name']


@app.route('/')
def home():
    # Lista de Relatórios por Workspace e links para escolha do usuário
    return render_template('index.html', table=wks_table)


@app.route('/workspace/workspace_id=<workspace_id>/report/report_id=<report_id>/name/report_name=<report_name>')
def rls_user(workspace_id, report_id, report_name):
    # Lista de RLS disponível e links para os relatórios embed
    config_file = 'report' + report_name + '__workspace_' + workspace_id + '.config'
    df_rls = pd.concat([rls_table,
                        '<a href="/relatorio/config_file=''' + config_file +
                        '''/json_file=''' + json_table[config_file] +
                        '''">Visualizar relatório</a>'''
                        ], ignore_index=False, axis=1)
    df_table = df_rls.to_html(classes='table100-head', index=False, escape=False, border=0)
    return render_template('index.html', table=df_table)


@app.route('/relatorio/config_file=<config_file>/json_file=<json_file>')
def relatorio(config_file, json_file):
    # Embedded do Relatório e Usuário Selecionado
    template = 'relatorios_individuais.html'
    with open('temp/' + config_file, "r") as fi:
        rep = json.load(fi)

    report_id = rep['report']['report_id']
    workspace_id = rep['report']['workspace_id']
    auth_token = bk.authenticate()
    response_backend = bk.embed_report(auth_token=auth_token,
                                       workspace_id=workspace_id,
                                       report_id=report_id,
                                       json_file=json_file)
    context = {'embed_url': response_backend["embed_url"][0],
               'embed_token': response_backend["report_token"][0],
               'report_id': response_backend["report_id"][0]}
    return render_template(template, **context)


if __name__ == '__main__':
    HOST = environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555

    app.run(HOST, PORT, debug=True)
