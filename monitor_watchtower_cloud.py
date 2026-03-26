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

ATIVOS_CPE = {
    "Windows Server 2022": "cpe:2.3:o:microsoft:windows_server_2022",
    "SQL Server 2022": "cpe:2.3:a:microsoft:sql_server:2022",
    "Cisco Catalyst 9500": "cpe:2.3:h:cisco:catalyst_9500",
    "Windows 11": "cpe:2.3:o:microsoft:windows_11",
    "Microsoft Edge": "cpe:2.3:a:microsoft:edge"
}

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

def salvar_na_planilha(data_pub, cve_id, ativo, descricao, score, severidade):
    arquivo_novo = not os.path.exists(PLANILHA_CSV)
    with open(PLANILHA_CSV, mode='a', newline='', encoding='utf-8-sig') as f:
        if arquivo_novo:
            f.write("sep=;\n")
            
        escritor = csv.writer(f, delimiter=';')
        
        if arquivo_novo:
            escritor.writerow(['Data Pub.', 'ID CVE', 'Ativo Impactado', 'Gravidade', 'Score', 'Descrição Técnica'])
        escritor.writerow([data_pub, cve_id, ativo, severidade, score, descricao])

def salvar_nova_vulnerabilidade(cve_id):
    with open(DB_VULNS, "a") as arquivo:
        arquivo.write(cve_id + "\n")

def enviar_alerta_pessoal(cve_id, descricao, ativo, score, severidade):
    cor_severidade = "#d9534f" if severidade in ["CRITICAL", "HIGH"] else "#f0ad4e"
    
    assunto = f"[WATCHTOWER] ALERTA {severidade}: {ativo} ({cve_id})"
    link_cve = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    corpo = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
        <h3 style="color: #d9534f;">[RELATÓRIO DE MONITORAMENTO - WATCHTOWER CONSULTING]</h3>
        
        <p>Identificamos uma nova vulnerabilidade mapeada para o ativo: <strong>{ativo}</strong>.</p>
        <hr style="border: 1px solid #ccc;">
        
        <p>Prezado Prof. Nilton,</p>
        
        <p>A nossa plataforma detectou uma falha publicada no NIST correspondente ao CPE do nosso ambiente:</p>
        <ul style="background-color: #f9f9f9; padding: 20px; border-radius: 5px; list-style-type: none;">
            <li style="margin-bottom: 10px;"> <strong>Ativo:</strong> {ativo}</li>
            <li style="margin-bottom: 10px;"> <strong>Gravidade:</strong> <span style="color: {cor_severidade}; font-weight: bold;">{severidade} (Score CVSS: {score})</span></li>
            <li style="margin-bottom: 10px;"> <strong>ID CVE:</strong> <a href="{link_cve}" style="color: #0275d8; font-weight: bold;">{cve_id} (Ver Análise Técnica Oficial)</a></li>
            <li style="margin-bottom: 10px;"> <strong>Descrição:</strong> {descricao}</li>
        </ul>
        
        <p><strong>Ação Recomendada:</strong> Analisar impacto no Banco Digital e verificar disponibilidade de patch de correção.</p>
        <hr style="border: 1px solid #ccc;">
        
        <p>Atenciosamente, <br>
        <strong>Equipe <a href="{link_watchtower}" style="color: #5cb85c; text-decoration: none;">WatchTower Consulting</a></strong></p>
    </body>
    </html>  """
    
    msg = MIMEText(corpo, 'html')
    msg['Subject'] = assunto
    msg['From'] = EMAIL
    msg['To'] = EMAIL

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, SENHA_APP)
            server.send_message(msg)
        log(f"Alerta enviado: {cve_id} ({severidade})")
    except Exception as e:
        log(f"Erro de e-mail: {e}")

def enviar_relatorio_final(total_novas, erros):
    assunto = f"[WATCHTOWER] Status da Ronda: {total_novas} novas falhas"
    corpo = f"""
    [STATUS DE MONITORAMENTO - WATCHTOWER CONSULTING]
    
    A ronda automática de segurança baseada em CPE (Common Platform Enumeration) foi concluída.
    
    - Novas vulnerabilidades detectadas e alertadas: {total_novas}
    - Erros de conexão com o NIST: {len(erros)} 
"""
    
    if erros:
        corpo += "\nDetalhes dos erros:\n"
        for erro in erros:
            corpo += f"- {erro}\n"
            
    corpo += "\nSistemas de monitoramento a operar normalmente.\n\nEquipe WatchTower Consulting"
    
    msg = MIMEText(corpo)
    msg['Subject'] = assunto
    msg['From'] = EMAIL
    msg['To'] = EMAIL

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(EMAIL, SENHA_APP)
            server.send_message(msg)
        log("Relatório de resumo enviado com sucesso.")
    except Exception as e:
        log(f"Erro ao enviar resumo: {e}")

def buscar_no_nist():
    conhecidas = carregar_vulnerabilidades_conhecidas()
    data_hoje = datetime.now(timezone.utc)
    
    DIAS_DE_BUSCA = 30
    
    data_alvo = data_hoje - timedelta(days=DIAS_DE_BUSCA)
    data_inicio = data_alvo.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'
    data_fim = data_hoje.strftime('%Y-%m-%dT%H:%M:%S.000') + '+00:00'
    
    log(f"Iniciando Busca de {DIAS_DE_BUSCA} dias via CPE...")
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'User-Agent': 'WatchTower-Monitor/2.0'} 

    total_novas_encontradas = 0
    erros_durante_busca = []

    for ativo, cpe_string in ATIVOS_CPE.items():
        log(f"A verificar: {ativo} (CPE: {cpe_string})...")
        
        params = {
            'virtualMatchString': cpe_string, 
            'pubStartDate': data_inicio, 
            'pubEndDate': data_fim
        }
        
        sucesso = False
        tentativas = 0
        
        # Sistema de Retry: Tenta até 3 vezes caso o NIST bloqueie temporariamente
        while not sucesso and tentativas < 3:
            try:
                response = requests.get(base_url, headers=headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    sucesso = True
                    vulnerabilidades = response.json().get('vulnerabilities', [])
                    log(f"   Encontradas {len(vulnerabilidades)} ocorrências válidas.")
                    
                    for item in vulnerabilidades:
                        cve = item.get('cve', {})
                        cve_id = cve.get('id')
                        
                        if cve_id not in conhecidas:
                            desc = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição')
                            data_p = cve.get('published', 'Data N/A')
                            
                            # Extração do Score CVSS v3.1 (ou fallback para v2)
                            metricas = cve.get('metrics', {})
                            score = "N/A"
                            severidade = "Desconhecida"
                            
                            if 'cvssMetricV31' in metricas:
                                score = metricas['cvssMetricV31'][0]['cvssData'].get('baseScore', 'N/A')
                                severidade = metricas['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'Desconhecida')
                            elif 'cvssMetricV2' in metricas:
                                score = metricas['cvssMetricV2'][0]['cvssData'].get('baseScore', 'N/A')
                                severidade = metricas['cvssMetricV2'][0].get('baseSeverity', 'Desconhecida')
                            
                            enviar_alerta_pessoal(cve_id, desc, ativo, score, severidade)
                            salvar_na_planilha(data_p, cve_id, ativo, desc, score, severidade)
                            salvar_nova_vulnerabilidade(cve_id)
                            total_novas_encontradas += 1
                else:
                    tentativas += 1
                    log(f"   [Aviso] NIST retornou código {response.status_code}. Tentativa {tentativas}/3...")
                    time.sleep(10) # Pausa mais longa se tomar rate limit (Erro 403)
                    
            except Exception as e:
                tentativas += 1
                log(f"   [Falha] Erro de rede: {e}. Tentativa {tentativas}/3...")
                time.sleep(5)
                
        if not sucesso:
            erro_msg = f"Falha ao buscar {ativo} após 3 tentativas."
            log(f"   {erro_msg}")
            erros_durante_busca.append(erro_msg)
            
        time.sleep(6) # Respeitar o limite público do NIST entre consultas
            
    log("Ronda finalizada com sucesso!")
    
    hora_atual = data_hoje.hour
    hora_do_relatorio = (hora_atual % 4 == 0)
    
    if total_novas_encontradas > 0 or erros_durante_busca or hora_do_relatorio:
        enviar_relatorio_final(total_novas_encontradas, erros_durante_busca)
    else:
        log("Ronda sem novidades. E-mail de status silenciado para evitar spam.")

"""if __name__ == "__main__":
    buscar_no_nist()"""

def resgatar_cve_perdida(cve_id, ativo):
 log(f"Iniciando resgate forçado da vulnerabilidade: {cve_id}...")
 base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
 headers = {'User-Agent': 'WatchTower-Monitor/2.0'}
 params = {'cveId': cve_id} # Busca cirúrgica direto pelo ID da CVE!

 try:
 response = requests.get(base_url, headers=headers, params=params, timeout=30)
 
 if response.status_code == 200:
 vulnerabilidades = response.json().get('vulnerabilities', [])
 
 if vulnerabilidades:
 cve = vulnerabilidades[0].get('cve', {})
 desc = cve.get('descriptions', [{}])[0].get('value', 'Sem descrição')
 
 # Extraindo o Score
 metricas = cve.get('metrics', {})
 score = "N/A"
 severidade = "Desconhecida"
 
 if 'cvssMetricV31' in metricas:
 score = metricas['cvssMetricV31'][0]['cvssData'].get('baseScore', 'N/A')
 severidade = metricas['cvssMetricV31'][0]['cvssData'].get('baseSeverity', 'Desconhecida')
 
 log(f"CVE Encontrada! Gravidade: {severidade}. Enviando e-mail...")
 # Chama a função que já existe no seu código para enviar o e-mail
 enviar_alerta_pessoal(cve_id, desc, ativo, score, severidade)
 log("Resgate concluído! E-mail enviado com sucesso.")
 else:
 log("O NIST não retornou dados para esse ID. Verifique se o CVE ID está correto.")
 else:
 log(f"Erro no NIST: Código {response.status_code}")
 
 except Exception as e:
 log(f"Falha na conexão de resgate: {e}")

if __name__ == "__main__":
    buscar_no_nist()
 
 # === OPÇÃO 2: Rodar o Resgate (Descomente a linha abaixo e coloque a CVE e o Ativo) ===
 resgatar_cve_perdida("CVE-2026-0898", "Microsoft Edge") 
