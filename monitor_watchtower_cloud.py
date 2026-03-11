import requests
import smtplib
import time
import sys
import os  
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

def salvar_nova_vulnerabilidade(cve_id):
    with open(DB_VULNS, "a") as arquivo:
        arquivo.write(cve_id + "\n")

def enviar_alerta_pessoal(cve_id, descricao, ativo):
    assunto = f"ALERTA WATCHTOWER: {ativo} ({cve_id})"
    
    corpo_do_email = f"""
    [WATCHTOWER CONSULTING - RELATÓRIO DE MONITORAMENTO AUTOMATIZADO]
    
    Identificamos uma nova vulnerabilidade crítica que impacta os ativos do banco.
    
    ------------------------------------------------------------
    Assunto: [WATCHTOWER] ALERTA DE SEGURANÇA - {ativo.upper()} - {cve_id}
    
    Prezado Prof. Nilton,
    
    Nossa plataforma de monitoramento detectou uma falha publicada no NIST:
    
    - Ativo Impactado: {ativo}
    - ID da Vulnerabilidade: {cve_id}
    - Descrição Técnica: {descricao}
    
    Impacto no Banco Digital: Risco de comprometimento de dados e indisponibilidade.
    Estamos avaliando as medidas de mitigação.
    
    Atenciosamente, 
    Equipe WatchTower Consulting
    "A vigilância que blinda o seu capital"
    ------------------------------------------------------------
    """
    
    msg = MIMEText(corpo_do_email)
    msg['Subject'] = assunto
    msg['From'] = EMAIL
    msg['To'] = EMAIL 

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, SENHA_APP)
            server.send_message(msg)
        log(f"Alerta enviado para {cve_id}!")
    except Exception as e:
        log(f"Erro de e-mail: {e}")

def buscar_no_nist():
    conhecidas = carregar_vulnerabilidades_conhecidas()
    data_hoje = datetime.now(timezone.utc)
    data_alvo = data_hoje - timedelta(days=2)
    
    data_inicio = data_alvo.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    data_fim = data_hoje.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    
    log(f"Ronda WatchTower iniciada...")
    
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'User-Agent': 'WatchTower-Monitor/1.0'}

    for ativo in ATIVOS:
        log(f"Verificando: {ativo}...")
        params = {
            'keywordSearch': ativo, 
            'pubStartDate': data_inicio, 
            'pubEndDate': data_fim
        }
        
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                dados = response.json()
                vulnerabilidades = dados.get('vulnerabilities', [])
                
                for item in vulnerabilidades:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id')
                    
                    if cve_id not in conhecidas:
                        desc = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição')
                        enviar_alerta_pessoal(cve_id, desc, ativo)
                        salvar_nova_vulnerabilidade(cve_id)
            
            # Pausa de segurança exigida pelo NIST
            time.sleep(6)
            
        except Exception as e:
            log(f"Falha técnica em {ativo}: {e}")
            
    log("Ronda finalizada com sucesso.")

if __name__ == "__main__":
    buscar_no_nist()
