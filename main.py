#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Importações necessárias
import sys
import time
import signal
import argparse # Já estava presente
from src.Osintgram import Osintgram # Já estava presente
from src import printcolors as pc # Já estava presente
from src import artwork # Já estava presente

# Importações para lidar com o desafio - Pode precisar ajustar a exceção específica
# Baseado em bibliotecas comuns, a exceção pode ser ClientError ou similar.
# Vamos usar Exception genérica como fallback, mas ClientError seria ideal se soubermos a biblioteca exata.
# from instagram_private_api import ClientError # Descomente e ajuste se Osintgram usar esta lib

is_windows = False

try:
    import gnureadline
except:
    is_windows = True
    import pyreadline


def printlogo():
    pc.printout(artwork.ascii_art, pc.YELLOW)
    pc.printout("\nVersion 1.1 - Developed by Giuseppe Criscione\n\n", pc.YELLOW)
    pc.printout("Type 'list' to show all allowed commands\n")
    pc.printout("Type 'FILE=y' to save results to files like '<target username>_<command>.txt (default is disabled)'\n")
    pc.printout("Type 'FILE=n' to disable saving to files'\n")
    pc.printout("Type 'JSON=y' to export results to a JSON files like '<target username>_<command>.json (default is "
                 "disabled)'\n")
    pc.printout("Type 'JSON=n' to disable exporting to files'\n")


def cmdlist():
    pc.printout("FILE=y/n\t")
    print("Enable/disable output in a '<target username>_<command>.txt' file'")
    pc.printout("JSON=y/n\t")
    print("Enable/disable export in a '<target username>_<command>.json' file'")
    pc.printout("addrs\t\t")
    print("Get all registered addressed by target photos")
    pc.printout("cache\t\t")
    print("Clear cache of the tool")
    pc.printout("captions\t")
    print("Get target's photos captions")
    pc.printout("commentdata\t")
    print("Get a list of all the comments on the target's posts")
    pc.printout("comments\t")
    print("Get total comments of target's posts")
    pc.printout("followers\t")
    print("Get target followers")
    pc.printout("followings\t")
    print("Get users followed by target")
    pc.printout("fwersemail\t")
    print("Get email of target followers")
    pc.printout("fwingsemail\t")
    print("Get email of users followed by target")
    pc.printout("fwersnumber\t")
    print("Get phone number of target followers")
    pc.printout("fwingsnumber\t")
    print("Get phone number of users followed by target")
    pc.printout("hashtags\t")
    print("Get hashtags used by target")
    pc.printout("info\t\t")
    print("Get target info")
    pc.printout("likes\t\t")
    print("Get total likes of target's posts")
    pc.printout("mediatype\t")
    print("Get target's posts type (photo or video)")
    pc.printout("photodes\t")
    print("Get description of target's photos")
    pc.printout("photos\t\t")
    print("Download target's photos in output folder")
    pc.printout("propic\t\t")
    print("Download target's profile picture")
    pc.printout("stories\t\t")
    print("Download target's stories")
    pc.printout("tagged\t\t")
    print("Get list of users tagged by target")
    pc.printout("target\t\t")
    print("Set new target")
    pc.printout("wcommented\t")
    print("Get a list of user who commented target's photos")
    pc.printout("wtagged\t\t")
    print("Get a list of user who tagged target")


# A função signal_handler já estava definida, mas vamos garantir que lida com a saída
def signal_handler(sig, frame):
    print('\n[!] Ctrl+C detectado. Encerrando Osintgram.')
    sys.exit(0)


def completer(text, state):
    options = [i for i in commands if i.startswith(text)]
    if state < len(options):
        return options[state]
    else:
        return None

def _quit():
    pc.printout("Goodbye!\n", pc.RED)
    sys.exit(0)

# Registrar o handler para o sinal de interrupção - Já estava presente
signal.signal(signal.SIGINT, signal_handler)

# Configuração do readline - Já estava presente
if is_windows:
    pyreadline.Readline().parse_and_bind("tab: complete")
    pyreadline.Readline().set_completer(completer)
else:
    gnureadline.parse_and_bind("tab: complete")
    gnureadline.set_completer(completer)

# Parsing de argumentos - Já estava presente
parser = argparse.ArgumentParser(description='Osintgram is a OSINT tool on Instagram. It offers an interactive shell '
                                             'to perform analysis on Instagram account of any users by its nickname ')
parser.add_argument('id', type=str,  # var = id
                    help='username')
parser.add_argument('-C','--cookies', help='clear\'s previous cookies', action="store_true")
parser.add_argument('-j', '--json', help='save commands output as JSON file', action='store_true')
parser.add_argument('-f', '--file', help='save output in a file', action='store_true')
parser.add_argument('-c', '--command', help='run in single command mode & execute provided command', action='store')
parser.add_argument('-o', '--output', help='where to store photos', action='store')

args = parser.parse_args()

# --- INÍCIO DA LÓGICA DE TRATAMENTO DE DESAFIO E LOGIN ---

# Variável para a instância da API (definida dentro do loop)
api = None
# Variável para controlar se o desafio foi completado (ou se o login foi bem-sucedido sem desafio)
challenge_completed = False

# Loop para tentar o login/acesso à API até que o desafio seja completado ou o login seja bem-sucedido
while not challenge_completed:
    try:
        # --- CÓDIGO ORIGINAL DE LOGIN/PRIMEIRA CHAMADA API ---
        # Esta linha cria a instância da classe Osintgram, que provavelmente
        # tenta fazer o login ou a primeira interação com a API do Instagram
        # em seu construtor (__init__).
        api = Osintgram(args.id, args.file, args.json, args.command, args.output, args.cookies)
        # Se a linha acima for bem-sucedida sem lançar uma exceção de desafio,
        # o login é considerado bem-sucedido para fins de desafio.
        # --- FIM DO CÓDIGO ORIGINAL DE LOGIN ---

        print("[+] Login bem-sucedido ou API acessada sem desafio.")
        challenge_completed = True # Sai do loop se não houver desafio

    # Captura o erro específico do desafio de segurança
    # O nome da exceção e a forma de acessar os detalhes (code, error_type, challenge_url)
    # dependem da biblioteca interna que a classe Osintgram usa.
    # Usamos Exception genérica como fallback, mas ClientError ou similar seria mais preciso.
    except Exception as e:
        # Verifique se o erro parece ser um desafio de segurança
        error_message = str(e).lower()
        # Verificação mais robusta do tipo de erro e código HTTP 400
        is_challenge_error = False
        challenge_url = None

        # Tenta verificar se a exceção tem atributos de erro comuns de APIs
        if hasattr(e, 'code') and e.code == 400 and hasattr(e, 'error_type') and e.error_type == 'checkpoint_challenge_required':
             is_challenge_error = True
             # Tenta obter o URL do desafio se disponível no objeto de exceção
             if hasattr(e, 'challenge') and isinstance(e.challenge, dict) and 'url' in e.challenge:
                 challenge_url = e.challenge['url']
             elif hasattr(e, 'challenge_url'): # Algumas libs podem ter um atributo direto
                  challenge_url = e.challenge_url

        # Se a verificação por atributos falhar, tenta buscar na string da mensagem de erro
        if not is_challenge_error and 'challenge_required' in error_message:
             is_challenge_error = True
             # Tenta parsear o URL da string da mensagem de erro
             import re
             match = re.search(r'(https://i\.instagram\.com/challenge/[^\s]+)', error_message)
             if match:
                 challenge_url = match.group(1)


        if is_challenge_error:
            print(f"[-] Desafio de segurança do Instagram detectado.")

            if challenge_url:
                print(f"[-] Por favor, complete o desafio neste link em um navegador:")
                print(f"[-] {challenge_url}")
            else:
                 print("[-] Não foi possível extrair o link do desafio automaticamente.")
                 print("[-] Por favor, verifique a saída do erro original acima para o link.")

            # Loop para pedir o código de verificação até que seja fornecido
            verification_code = ""
            while not verification_code:
                verification_code = input("[?] Digite o código de verificação do Instagram: ").strip()
                if not verification_code:
                    print("[-] Código não pode ser vazio. Tente novamente.")

            try:
                # --- CHAME A FUNÇÃO DA API PARA COMPLETAR O DESAFIO AQUI ---
                # Esta é a parte CRUCIAL que depende de como a classe Osintgram
                # ou a biblioteca interna que ela usa lida com a conclusão de desafios.
                # Você precisa encontrar o método correto na instância 'api' (que pode
                # ter sido parcialmente criada mesmo com o erro de desafio)
                # para enviar o código de verificação.
                #
                # Você pode precisar inspecionar o código da classe Osintgram em src/Osintgram.py
                # para ver como ela lida com desafios. Procure por métodos que recebem
                # um código ou URL de desafio.
                #
                # Exemplo COMUM (pode ser diferente para Osintgram):
                if api and hasattr(api, 'complete_challenge'): # Verifica se 'api' foi criada e tem o método
                    if challenge_url:
                         # Algumas libs precisam do URL e do código
                         api.complete_challenge(challenge_url, verification_code)
                    else:
                         # Outras podem só precisar do código
                         api.complete_challenge(verification_code)
                elif api and hasattr(api, 'send_challenge_code'): # Outro nome de método comum
                     api.send_challenge_code(verification_code)
                else:
                     print("[-] Não foi possível encontrar um método conhecido para completar o desafio na instância da API.")
                     print("[-] Por favor, verifique o código fonte da classe Osintgram.")
                     # Se não puder chamar o método, o loop continuará, mas o usuário sabe o problema.
                     # sys.exit(1) # Não sair aqui, permite tentar novamente após resolução manual

                print("[+] Código de verificação enviado. Tentando login novamente...")
                # Pequena pausa antes de tentar novamente para dar tempo ao Instagram processar
                time.sleep(5)

            except Exception as challenge_error:
                print(f"[-] Erro ao tentar completar o desafio: {challenge_error}")
                print("[-] Por favor, complete o desafio manualmente no navegador e tente executar o script novamente.")
                # Não sair aqui, o loop principal tentará novamente, mas o usuário foi avisado
                # sys.exit(1) # Remover esta linha para permitir nova tentativa manual

        else:
            # Se for outro tipo de erro, imprima e saia
            print(f"[-] Ocorreu um erro inesperado durante o login/acesso à API: {e}")
            sys.exit(1) # Sair em caso de outros erros

# --- FIM DA LÓGICA DE TRATAMENTO DE DESAFIO E LOGIN ---


# --- CÓDIGO ORIGINAL RESTANTE DO Osintgram ---
# Este código só será alcançado se o loop 'while not challenge_completed' terminar,
# ou seja, após o login bem-sucedido ou o desafio ser completado.
# Ele contém a lógica principal do shell interativo ou execução de comando único.

# O objeto 'api' agora deve estar autenticado/inicializado se o loop terminou com sucesso.
# O código original que usa 'api' para executar comandos deve vir aqui.

if not args.command:
    printlogo()

# O loop principal de comandos do Osintgram
while True:
    if args.command:
        cmd = args.command
        _cmd = commands.get(args.command)
    else:
        # Remova ou comente estas linhas se já foram configuradas no início
        # signal.signal(signal.SIGINT, signal_handler)
        # if is_windows:
        #     pyreadline.Readline().parse_and_bind("tab: complete")
        #     pyreadline.Readline().set_completer(completer)
        # else:
        #     gnureadline.parse_and_bind("tab: complete")
        #     gnureadline.set_completer(completer)
        pc.printout("Run a command: ", pc.YELLOW)
        cmd = input()

        _cmd = commands.get(cmd)

    if _cmd:
        # Chama o método correspondente na instância 'api'
        # Certifique-se de que os métodos em 'commands' usam a instância 'api'
        # que foi autenticada.
        try:
            _cmd() # Executa o comando usando a instância 'api'
        except Exception as cmd_error:
            pc.printout(f"[-] Erro ao executar o comando '{cmd}': {cmd_error}\n", pc.RED)

    elif cmd == "FILE=y":
        # Verifica se 'api' foi inicializada antes de chamar o método
        if api:
            api.set_write_file(True)
        else:
            pc.printout("[-] API não inicializada. Login falhou.\n", pc.RED)
    elif cmd == "FILE=n":
         if api:
            api.set_write_file(False)
         else:
            pc.printout("[-] API não inicializada. Login falhou.\n", pc.RED)
    elif cmd == "JSON=y":
         if api:
            api.set_json_dump(True)
         else:
            pc.printout("[-] API não inicializada. Login falhou.\n", pc.RED)
    elif cmd == "JSON=n":
         if api:
            api.set_json_dump(False)
         else:
            pc.printout("[-] API não inicializada. Login falhou.\n", pc.RED)
    elif cmd == "":
        print("")
    else:
        pc.printout("Unknown command\n", pc.RED)

    if args.command:
        break

# --- FIM DO CÓDIGO ORIGINAL RESTANTE DO Osintgram ---