import requests
import smtplib
import time
import sys
import os
import csv
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone

EMAIL = os.environ.get("EMAIL_USER")
SENHA_APP = os.environ.get("EMAIL_PASS")

ATIVOS = [
    "Windows Server 2022", 
    "SQL Server 2022", 
    "Cisco Catalyst 9500", 
    "Windows 11 Pro", 
    "Microsoft Edge"
]

DB_VULNS = "memorizadas.txt"
PLANILHA_CSV = "historico_vulnerabilidades.csv"

def log(mensagem):
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {mensagem}")
    sys.stdout.flush() 

def carregar_vulnerabilidades_conhecidas():
    try:
        with open(DB_VULNS, "r") as arquivo:
            return set(arquivo.read().splitlines())
    except FileNotFoundError:
        return set()

def salvar_na_planilha(data_pub, cve_id, ativo, descricao):
    arquivo_novo = not os.path.exists(PLANILHA_CSV)
    
    with open(PLANILHA_CSV, mode='a', newline='', encoding='utf-8-sig') as f:
        escritor = csv.writer(f, delimiter=';')
        
        if arquivo_novo:
            escritor.writerow(['Data Pub.', 'ID CVE', 'Ativo Impactado', 'Descrição Técnica'])
        escritor.writerow([data_pub, cve_id, ativo, descricao])

def salvar_nova_vulnerabilidade(cve_id):
    with open(DB_VULNS, "a") as arquivo:
        arquivo.write(cve_id + "\n")

def enviar_alerta_pessoal(cve_id, descricao, ativo):
    assunto = f"[WATCHTOWER] ALERTA: {ativo} ({cve_id})"
    
    corpo = f"""
    [RELATÓRIO DE MONITORAMENTO - WATCHTOWER CONSULTING]
    
    Identificamos uma vulnerabilidade crítica para o ativo: {ativo}.
    Gentileza copiar o texto abaixo e enviar ao professor o quanto antes

    ------------------------------------------------------------
    Prezado Prof. Nilton,
    
    Nossa plataforma detectou uma falha publicada no NIST:
    
    - Ativo: {ativo}
    - ID: {cve_id}
    - Descrição: {descricao}
    
    Impacto no Banco Digital: Risco de comprometimento de dados e indisponibilidade.
    ------------------------------------------------------------
    
    Atenciosamente, 
    Equipe WatchTower Consulting
    "A vigilância que blinda o seu capital"
    """
    
    msg = MIMEText(corpo)
    msg['Subject'] = assunto
    msg['From'] = EMAIL
    msg['To'] = EMAIL 

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, SENHA_APP)
            server.send_message(msg)
        log(f" Alerta enviado para o e-mail: {cve_id}")
    except Exception as e:
        log(f" Erro ao enviar e-mail: {e}")

def buscar_no_nist():
    conhecidas = carregar_vulnerabilidades_conhecidas()
    data_hoje = datetime.now(timezone.utc)
    
    DIAS_DE_BUSCA = 110 
    
    data_alvo = data_hoje - timedelta(days=DIAS_DE_BUSCA)
    data_inicio = data_alvo.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    data_fim = data_hoje.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    log(f" Iniciando Busca Histórica de {DIAS_DE_BUSCA} dias...")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'User-Agent': 'WatchTower-Monitor/1.0'}

    for ativo in ATIVOS:
        log(f" Verificando: {ativo}...")
        params = {
            'keywordSearch': ativo, 
            'pubStartDate': data_inicio, 
            'pubEndDate': data_fim
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                vulnerabilidades = response.json().get('vulnerabilities', [])
                log(f" Encontradas {len(vulnerabilidades)} ocorrências.")
                
                for item in vulnerabilidades:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    
                    if cve_id not in conhecidas:
                        desc = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição')
                        data_p = cve.get('published', 'Data N/A')
                        
                        enviar_alerta_pessoal(cve_id, desc, ativo)
                        salvar_na_planilha(data_p, cve_id, ativo, desc)
                        salvar_nova_vulnerabilidade(cve_id)
            else:
                log(f" Erro no NIST (Código: {response.status_code})")
            
            time.sleep(6)
            
        except Exception as e:
            log(f" Falha técnica ao buscar {ativo}: {e}")
            
    log(" Ronda finalizada com sucesso!")

if __name__ == "__main__":
    buscar_no_nist()
